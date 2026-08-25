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

# The cert checker script + the out-of-band scan loop and entrypoint.
COPY check_certs.py /usr/local/bin/check_certs.py
COPY scan_loop.sh /usr/local/bin/scan_loop.sh
COPY entrypoint.sh /usr/local/bin/tls-entrypoint.sh
RUN chmod 0755 /usr/local/bin/check_certs.py \
                /usr/local/bin/scan_loop.sh \
                /usr/local/bin/tls-entrypoint.sh

# Zabbix agent UserParameters. The image's entrypoint configures the agent to
# Include /etc/zabbix/zabbix_agentd.d/*.conf (NOT zabbix_agent2.d/*.conf, which
# is only scanned for plugins.d), so the UserParameter file must live here.
COPY zabbix/userparameter_tls_monitor.conf /etc/zabbix/zabbix_agentd.d/tls_monitor.conf

# Cache written by `check_certs.py --scan` and read by the agent. It lives in a
# dedicated directory (NOT /tmp, which the Zabbix agent uses for its own
# temporary files) so the two never collide. With a read-only root filesystem,
# mount a separate emptyDir at /var/cache/tlsmonitor.
# We create the dir now (as root) so UID 1997 can write to it even before the
# volume is mounted; SCAN_INTERVAL controls how often the loop rescans.
RUN mkdir -p /var/cache/tlsmonitor \
    && chown 1997:1997 /var/cache/tlsmonitor \
    && chmod 0755 /var/cache/tlsmonitor

ENV DOMAINS_FILE=/config/domains.txt \
    CACHE_FILE=/var/cache/tlsmonitor/tls_certs.json \
    SCAN_INTERVAL=300 \
    WARNING_DAYS=15 \
    DEFAULT_PORT=443

# Drop back to the unprivileged zabbix user provided by the base image.
USER 1997

# Start the background scan loop, then hand off to the stock agent entrypoint.
ENTRYPOINT ["/usr/local/bin/tls-entrypoint.sh"]
CMD ["/usr/sbin/zabbix_agent2", "--foreground", "-c", "/etc/zabbix/zabbix_agent2.conf"]
