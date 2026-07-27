#!/bin/sh
# APEX edge TLS cert expiry watchdog (Phase: Vault PKI auto-renew safety net).
#
# The cert at /etc/ssl/apexscanner/combined.pem is auto-renewed by the
# vault-agent.service (AppRole -> Vault PKI, 30-day certs). This watchdog is the
# backstop: it does NOT renew, it SCREAMS if renewal has silently failed for any
# reason (agent down, secret_id lost, Vault unreachable, template stuck), so a
# human is alerted days before the cert actually expires — the exact failure
# mode that took the edge down on 2026-07-26.
#
# Install as a daily systemd timer (see cert-expiry-check.{service,timer}).
# Exit non-zero + logs to journal on WARN/CRIT so alerting can hook the unit.
set -eu

CERT="${CERT:-/etc/ssl/apexscanner/combined.pem}"
WARN_DAYS="${WARN_DAYS:-10}"
CRIT_DAYS="${CRIT_DAYS:-5}"

if [ ! -f "$CERT" ]; then
    echo "CRITICAL: cert file missing: $CERT" >&2
    exit 2
fi

end_epoch=$(date -d "$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)" +%s)
now_epoch=$(date +%s)
days_left=$(( (end_epoch - now_epoch) / 86400 ))

# Also confirm the renewer is alive — a dead agent is the real root cause.
agent_state=$(systemctl is-active vault-agent 2>/dev/null || echo "unknown")

msg="APEX edge cert: ${days_left}d left (expiry $(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)); vault-agent=${agent_state}"

if [ "$days_left" -le "$CRIT_DAYS" ] || [ "$agent_state" != "active" ]; then
    echo "CRITICAL: $msg" >&2
    logger -t apex-cert-watchdog -p daemon.err "CRITICAL: $msg"
    exit 2
elif [ "$days_left" -le "$WARN_DAYS" ]; then
    echo "WARNING: $msg" >&2
    logger -t apex-cert-watchdog -p daemon.warning "WARNING: $msg"
    exit 1
fi

echo "OK: $msg"
logger -t apex-cert-watchdog -p daemon.info "OK: $msg"
exit 0
