# Zabbix agent 2 (active) + nmap + the Python cert checker, in one image.
#
# The official zabbix/zabbix-agent2 image is multi-arch (amd64 + arm64), so this
# builds for both. We add python3, nmap and our UserParameter so the agent can
# report the cert.sh-compatible JSON to the Zabbix server.
#
# Alpine variant keeps the image small; nmap + python3 come from apk.
FROM zabbix/zabbix-agent2:alpine-7.0-latest

USER root

RUN apk add --no-cache python3 nmap nmap-scripts

# The cert checker script.
COPY check_certs.py /usr/local/bin/check_certs.py
RUN chmod 0755 /usr/local/bin/check_certs.py

# Zabbix agent UserParameters (mounted into the agent include dir).
COPY zabbix/userparameter_tls_monitor.conf /etc/zabbix/zabbix_agent2.d/tls_monitor.conf

# Default domains file location (overridden by the ConfigMap mount at /config).
ENV DOMAINS_FILE=/config/domains.txt \
    WARNING_DAYS=15 \
    DEFAULT_PORT=443

# Drop back to the unprivileged zabbix user provided by the base image.
USER 1997
