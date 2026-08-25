#!/usr/bin/env python3
"""Check TLS certificates for a list of domains and print cert.sh-compatible JSON.

This is the Python port of cert.sh: it shells out to `nmap --script ssl-cert`
exactly like the original, parses the "Not valid after:" field, and prints a
JSON array with the very same fields:

    {
      "domain": "example.com",
      "days_left": 42,
      "status": "OK",          # OK | WARNING | ERROR
      "scan_time": 0,          # seconds the check took
      "expires": "2026-10-27T22:17:21"
    }

Scanning is decoupled from serving so the Zabbix agent never blocks:

    --scan       run nmap against every domain and atomically write the JSON
                 array to CACHE_FILE. Meant to run periodically (cron / loop),
                 NOT from the agent.
    (no args)    print the cached JSON array (the `tls.certs.raw` item). This
                 only reads CACHE_FILE, so it returns instantly and never hits
                 the agent's Timeout.
    --discovery  print a Zabbix low-level discovery document
                 ({"data": [{"{#DOMAIN}": "..."}]}) so the server can
                 auto-create per-domain items and triggers.

This split fixes the "Timeout occurred while gathering data" error: the slow
nmap work happens out of band, and the agent only reads a file.

Configuration is via environment variables only (safe for a public repo):

    DOMAINS_FILE   path to newline-separated domains (default /config/domains.txt)
    CACHE_FILE     where --scan writes / readers read (default /var/cache/tlsmonitor/tls_certs.json)
    WARNING_DAYS   status becomes WARNING under this many days left (default 15)
    MAX_RETRIES    nmap attempts per domain (default 3)
    RETRY_DELAY    seconds between retries (default 2)
    DEFAULT_PORT   port scanned when a domain has none (default 443)
    NMAP_BIN       nmap executable (default "nmap")
    MAX_WORKERS    parallel nmap scans during --scan (default 8)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# nmap prints e.g.:  "| ssl-cert: ... Not valid after:  2026-10-27T22:17:21"
NOT_VALID_AFTER = re.compile(r"Not valid after:\s*(\S+)")


def env_str(key: str, default: str) -> str:
    return os.environ.get(key, "").strip() or default


def env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, "").strip())
    except (TypeError, ValueError):
        return default


def load_domains(path: str) -> list[str]:
    """Read domains, one per line. Ignore blanks and '#' comments; dedupe."""
    seen: set[str] = set()
    domains: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if entry not in seen:
                seen.add(entry)
                domains.append(entry)
    return domains


def split_host_port(entry: str, default_port: int) -> tuple[str, int]:
    """Return (host, port). Supports 'host', 'host:port' and '[ipv6]:port'."""
    if entry.startswith("["):
        host, _, rest = entry[1:].partition("]")
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if entry.count(":") == 1:
        host, _, port = entry.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return entry, default_port
    return entry, default_port


def run_nmap(nmap_bin: str, host: str, port: int, retries: int, delay: int) -> str | None:
    """Run nmap ssl-cert, retrying like cert.sh. Return the expiry string or None."""
    for attempt in range(1, retries + 1):
        try:
            proc = subprocess.run(
                [nmap_bin, "--script", "ssl-cert", "-p", str(port), host],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            match = NOT_VALID_AFTER.search(proc.stdout)
            if match:
                return match.group(1)
        except (subprocess.TimeoutExpired, OSError):
            pass

        if attempt < retries:
            time.sleep(delay)
    return None


def parse_expiry(raw: str) -> datetime:
    """Parse nmap's ISO-like expiry, e.g. '2026-10-27T22:17:21' (UTC)."""
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def check_domain(entry: str, cfg: dict) -> dict:
    start = time.monotonic()
    result = {"domain": entry, "days_left": -1, "status": "ERROR", "scan_time": 0, "expires": ""}

    try:
        host, port = split_host_port(entry, cfg["default_port"])
        raw = run_nmap(cfg["nmap_bin"], host, port, cfg["max_retries"], cfg["retry_delay"])
        if raw:
            expiry = parse_expiry(raw)
            days_left = (expiry - datetime.now(timezone.utc)).days
            result["days_left"] = days_left
            result["expires"] = expiry.strftime("%Y-%m-%dT%H:%M:%S")
            result["status"] = "WARNING" if days_left < cfg["warning_days"] else "OK"
    except Exception:
        result.update(days_left=-1, status="ERROR", expires="")
    finally:
        result["scan_time"] = int(time.monotonic() - start)

    return result


def scan_all(domains: list[str], cfg: dict) -> list[dict]:
    """Scan every domain in parallel and return the cert.sh-compatible list.

    Order is preserved so the discovery list and the raw report stay aligned.
    """
    workers = max(1, min(cfg["max_workers"], len(domains) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda entry: check_domain(entry, cfg), domains))


def write_cache(path: str, results: list[dict]) -> None:
    """Atomically write the JSON array so readers never see a partial file."""
    payload = json.dumps(results)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tls_certs.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_cache(path: str) -> str:
    """Return the cached JSON array text, or an empty array if not yet scanned."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip() or "[]"
    except OSError:
        return "[]"


def main() -> int:
    cfg = {
        "domains_file": env_str("DOMAINS_FILE", "/config/domains.txt"),
        "cache_file": env_str("CACHE_FILE", "/var/cache/tlsmonitor/tls_certs.json"),
        "warning_days": env_int("WARNING_DAYS", 15),
        "max_retries": env_int("MAX_RETRIES", 3),
        "retry_delay": env_int("RETRY_DELAY", 2),
        "default_port": env_int("DEFAULT_PORT", 443),
        "max_workers": env_int("MAX_WORKERS", 8),
        "nmap_bin": env_str("NMAP_BIN", "nmap"),
    }

    args = sys.argv[1:]
    discovery = "--discovery" in args
    scan = "--scan" in args

    # Readers (agent side) only touch the cache file, so they return instantly.
    if not scan:
        if discovery:
            try:
                domains = load_domains(cfg["domains_file"])
            except OSError as exc:
                print(
                    f"ERROR: cannot read domains file {cfg['domains_file']}: {exc}",
                    file=sys.stderr,
                )
                return 1
            data = {"data": [{"{#DOMAIN}": d} for d in domains]}
            json.dump(data, sys.stdout)
            sys.stdout.write("\n")
            return 0

        sys.stdout.write(read_cache(cfg["cache_file"]))
        sys.stdout.write("\n")
        return 0

    # Scanner (out of band): do the slow nmap work and refresh the cache.
    try:
        domains = load_domains(cfg["domains_file"])
    except OSError as exc:
        print(f"ERROR: cannot read domains file {cfg['domains_file']}: {exc}", file=sys.stderr)
        return 1

    if shutil.which(cfg["nmap_bin"]) is None:
        print(f"ERROR: nmap not found ({cfg['nmap_bin']})", file=sys.stderr)
        return 1

    results = scan_all(domains, cfg)

    try:
        write_cache(cfg["cache_file"], results)
    except OSError as exc:
        print(f"ERROR: cannot write cache file {cfg['cache_file']}: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
