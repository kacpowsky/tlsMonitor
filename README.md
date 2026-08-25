# tlsMonitor

A tiny TLS certificate checker. It is the Python port of [`cert.sh`](./cert.sh):
it runs `nmap --script ssl-cert` against a list of domains and prints the exact
same **cert.sh-compatible JSON** so a **Zabbix server** can read it.

It is meant to run as a pod in **Kubernetes**:

- domains come from a **ConfigMap** (`domains.txt`),
- a background loop in the pod runs the scan periodically and writes the JSON
  to a small **cache file**,
- a **Zabbix agent (active)** in the same pod serves that cache via a
  `UserParameter` and reports the JSON to the Zabbix server.

Scanning is **decoupled** from serving: the agent only ever reads the cache
file, so `tls.certs.raw` returns instantly and never triggers
`Timeout occurred while gathering data`. The slow `nmap` work happens out of
band in the scan loop.

The image is built for **amd64 and arm64** in **GitHub Actions**. No secrets or
credentials are stored in the repo — everything sensitive is an env var.

## Output format (same as cert.sh)

```json
[
  {
    "domain": "example.com",
    "days_left": 63,
    "status": "OK",
    "scan_time": 0,
    "expires": "2026-10-27T22:17:21"
  }
]
```

- `status`: `OK` | `WARNING` (expires within `WARNING_DAYS`, or already expired)
  | `ERROR` (check failed).
- `days_left`: whole days until expiry, `-1` on error.

## The checker: `check_certs.py`

Pure standard library (only shells out to `nmap`). Configuration via env vars:

| Variable | Default | Description |
| --- | --- | --- |
| `DOMAINS_FILE` | `/config/domains.txt` | Path to the domains list. |
| `CACHE_FILE` | `/var/cache/tlsmonitor/tls_certs.json` | Where `--scan` writes and readers read. |
| `WARNING_DAYS` | `15` | `WARNING` when fewer days remain. |
| `MAX_RETRIES` | `3` | nmap attempts per domain. |
| `RETRY_DELAY` | `2` | Seconds between retries. |
| `DEFAULT_PORT` | `443` | Port used when a domain omits one. |
| `MAX_WORKERS` | `8` | Parallel nmap scans during `--scan`. |
| `NMAP_BIN` | `nmap` | nmap executable. |

The script has three modes:

```bash
cp domains.txt.example domains.txt   # your local list (git-ignored)

# 1) Scan every domain (slow) and refresh the cache. Run this periodically.
DOMAINS_FILE=./domains.txt CACHE_FILE=./tls_certs.json \
  python3 check_certs.py --scan

# 2) Serve the cached JSON array (the tls.certs.raw item). Instant, no nmap.
CACHE_FILE=./tls_certs.json python3 check_certs.py

# 3) Discovery document for Zabbix LLD (reads the domains file, no nmap):
DOMAINS_FILE=./domains.txt python3 check_certs.py --discovery
```

Before the first `--scan`, the reader returns an empty array (`[]`).

Domains file format:

```text
# comments start with '#'
example.com
cloudflare.com
github.com:443
```

## Zabbix integration

Two active-check UserParameters (`zabbix/userparameter_tls_monitor.conf`):

| Key | Returns |
| --- | --- |
| `tls.certs.raw` | Full JSON array from the cache (master item). |
| `tls.certs.discovery` | LLD document: `{"data":[{"{#DOMAIN}":"..."}]}`. |

Both commands **only read files** (the cache and the domains list) — they never
run `nmap` — so they return instantly and never hit the agent's `Timeout`. The
cache is refreshed by the background scan loop (`check_certs.py --scan`, every
`SCAN_INTERVAL` seconds).

Per-domain items/triggers are derived **server-side** from `tls.certs.raw` using
dependent items + JSONPath. Import the template
`zabbix/template_tls_monitor.yaml` on your Zabbix server and link it to the
`tls-monitor` host.

## Build the image

The image bundles Zabbix agent 2 (active) + python3 + nmap + the checker:

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t tlsmonitor:local --load .
```

## Deploy to Kubernetes

Kubernetes manifests are intentionally **not** stored in this repo — they are
environment-specific (server address, namespace, host name) and belong in your
own deployment/GitOps repo. You need two things:

1. A **ConfigMap** exposing `domains.txt` at `/config/domains.txt`
   (one domain per line, see `domains.txt.example`).
2. A **Deployment** running this image with the Zabbix env vars below.
3. A **writable cache directory** at `/var/cache/tlsmonitor`. This is a
   **dedicated** volume, separate from the `/tmp` the Zabbix agent uses for its
   own temporary files, so the two never collide. With a read-only root
   filesystem, mount an `emptyDir` there (or point `CACHE_FILE` at another
   writable mount). The scan loop writes there; the agent reads from it.

Example volume wiring (keep the agent's existing `/tmp` mount untouched):

```yaml
volumeMounts:
  - name: tls-cache
    mountPath: /var/cache/tlsmonitor
  # ... your existing zabbix /tmp mount stays as-is ...
volumes:
  - name: tls-cache
    emptyDir: {}
```

The scan cadence is controlled by `SCAN_INTERVAL` (seconds, default `300`); an
initial scan runs at startup so the cache is warm before the first agent poll.

Change monitored domains by editing the ConfigMap; the next scan picks it up.

### Where is the Zabbix server address configured?

You do **not** edit `zabbix_agent2.conf` by hand. The official
`zabbix/zabbix-agent2` image renders the config from `ZBX_*` environment
variables on startup, so the server address lives in the Deployment `env:`
block:

| Env var | Maps to `zabbix_agent2.conf` | Purpose |
| --- | --- | --- |
| `ZBX_SERVER_HOST` | `Server` **and** `ServerActive` | IP/DNS of the Zabbix server/proxy. The entrypoint derives `ServerActive` (active checks) from it. |
| `ZBX_SERVER_PORT` | port used in `ServerActive` | Defaults to `10051`; set only if different. |
| `ZBX_ACTIVE_ALLOW` | enables active checks | Default `true`. |
| `ZBX_HOSTNAME` | `Hostname` | Must match the host name configured on the Zabbix server (or use autoregistration). |
| `ZBX_REFRESHACTIVECHECKS` | `RefreshActiveChecks` | How often (s) the agent refreshes its item list. |

Plus the checker's own env vars (`DOMAINS_FILE`, `CACHE_FILE`, `SCAN_INTERVAL`,
`WARNING_DAYS`, `DEFAULT_PORT`).

So "the agent knows the server" because `ZBX_SERVER_HOST` becomes `ServerActive`
inside the container. For a non-default port, set `ZBX_SERVER_PORT`; for several
servers/clusters, use `ZBX_ACTIVESERVERS`.

## CI / CD

`.github/workflows/build-and-push.yaml` builds and pushes multi-arch images to
GHCR. The registry **user and token are resolved dynamically** —
`username: ${{ github.actor }}`, `password: ${{ secrets.GITHUB_TOKEN }}`.
No credentials live in the repository.

## Security notes

- No secrets/tokens in the code — only env vars.
- Runs as a non-root user (UID 1997), all capabilities dropped, and works with
  a read-only root filesystem (the only extra writable path is the dedicated
  cache dir `/var/cache/tlsmonitor`).
- The only thing written to disk is the short-lived cache in
  `/var/cache/tlsmonitor` (ephemeral `emptyDir`, separate from the agent's
  `/tmp`); it holds public certificate expiry data, no secrets.
