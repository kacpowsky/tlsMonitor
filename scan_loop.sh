#!/bin/sh

set -eu

SCAN_INTERVAL="${SCAN_INTERVAL:-300}"
CHECK_BIN="${CHECK_BIN:-/usr/local/bin/check_certs.py}"

log() {
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') scan_loop: $*"
}

log "starting; interval=${SCAN_INTERVAL}s cache=${CACHE_FILE:-/var/cache/tlsmonitor/tls_certs.json}"

while true; do
    if "$CHECK_BIN" --scan; then
        log "scan ok"
    else
        log "scan failed (exit $?)"
    fi
    sleep "$SCAN_INTERVAL"
done
