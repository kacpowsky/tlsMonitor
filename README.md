# tlsMonitor

A tiny TLS certificate checker. It is the Python port of [`cert.sh`](./cert.sh):
it runs `nmap --script ssl-cert` against a list of domains and prints the exact
same **cert.sh-compatible JSON** so a **Zabbix server** can read it.

It is meant to run as a pod in **Kubernetes**:

- domains come from a **ConfigMap** (`domains.txt`),
- a **Zabbix agent (active)** in the pod runs the check via a `UserParameter`
  and reports the JSON to the Zabbix server,
- nothing is written to disk, there is no daemon and no extra service.

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
| `WARNING_DAYS` | `15` | `WARNING` when fewer days remain. |
| `MAX_RETRIES` | `3` | nmap attempts per domain. |
| `RETRY_DELAY` | `2` | Seconds between retries. |
| `DEFAULT_PORT` | `443` | Port used when a domain omits one. |
| `NMAP_BIN` | `nmap` | nmap executable. |

Run it directly:

```bash
cp domains.txt.example domains.txt   # your local list (git-ignored)
DOMAINS_FILE=./domains.txt python3 check_certs.py
# discovery document for Zabbix LLD:
DOMAINS_FILE=./domains.txt python3 check_certs.py --discovery
```

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
| `tls.certs.raw` | Full JSON array (master item). |
| `tls.certs.discovery` | LLD document: `{"data":[{"{#DOMAIN}":"..."}]}`. |

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

Change monitored domains by editing the ConfigMap; the next check picks it up.

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

Plus the checker's own env vars (`DOMAINS_FILE`, `WARNING_DAYS`, `DEFAULT_PORT`).

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
- Runs as a non-root user, read-only root filesystem, all capabilities dropped.
- Nothing persisted to disk; output goes straight to the Zabbix server.
