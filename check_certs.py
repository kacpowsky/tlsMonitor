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

It is meant to be called by a Zabbix agent (active) UserParameter; the Zabbix
server reads the JSON directly. Nothing is written to disk.

With --discovery it instead prints a Zabbix low-level discovery document
({"data": [{"{#DOMAIN}": "..."}]}) so the server can auto-create per-domain
items and triggers.

Configuration is via environment variables only (safe for a public repo):

    DOMAINS_FILE   path to newline-separated domains (default /config/domains.txt)
    WARNING_DAYS   status becomes WARNING under this many days left (default 15)
    MAX_RETRIES    nmap attempts per domain (default 3)
    RETRY_DELAY    seconds between retries (default 2)
    DEFAULT_PORT   port scanned when a domain has none (default 443)
    NMAP_BIN       nmap executable (default "nmap")
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
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


def main() -> int:
    cfg = {
        "domains_file": env_str("DOMAINS_FILE", "/config/domains.txt"),
        "warning_days": env_int("WARNING_DAYS", 15),
        "max_retries": env_int("MAX_RETRIES", 3),
        "retry_delay": env_int("RETRY_DELAY", 2),
        "default_port": env_int("DEFAULT_PORT", 443),
        "nmap_bin": env_str("NMAP_BIN", "nmap"),
    }

    discovery = "--discovery" in sys.argv[1:]

    try:
        domains = load_domains(cfg["domains_file"])
    except OSError as exc:
        print(f"ERROR: cannot read domains file {cfg['domains_file']}: {exc}", file=sys.stderr)
        return 1

    # Low-level discovery: just the list of domains, no scanning needed.
    if discovery:
        data = {"data": [{"{#DOMAIN}": d} for d in domains]}
        json.dump(data, sys.stdout)
        sys.stdout.write("\n")
        return 0

    if shutil.which(cfg["nmap_bin"]) is None:
        print(f"ERROR: nmap not found ({cfg['nmap_bin']})", file=sys.stderr)
        return 1

    results = [check_domain(entry, cfg) for entry in domains]

    json.dump(results, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
