#!/bin/sh
set -eu

# Warm and keep the cache fresh in the background.
/usr/local/bin/scan_loop.sh &

# Hand off to the upstream Zabbix agent 2 entrypoint (renders config from ZBX_*
# env vars and execs the agent). Default CMD matches the base image.
exec /usr/bin/docker-entrypoint.sh "$@"
