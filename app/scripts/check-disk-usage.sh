#!/bin/sh
# APEX disk watchdog.
#
# Exists because a silent leak (Syft/Grype stereoscope scratch dirs in the batch
# workers' /tmp) grew to ~142 GB and took /opt from healthy to 98% full with no
# warning — the platform has no deployed monitoring, so nothing noticed until a
# human looked. This does not clean anything; it screams early.
#
# Reports per-filesystem usage plus the docker-level breakdown and the top
# container writable layers, so the first line of an alert already points at the
# culprit. Exit 1 = WARN, 2 = CRIT (so a systemd timer / alerting can hook it).
set -eu

WARN_PCT="${WARN_PCT:-80}"
CRIT_PCT="${CRIT_PCT:-90}"
MOUNTS="${MOUNTS:-/ /opt}"

rc=0
for mp in $MOUNTS; do
    [ -d "$mp" ] || continue
    pct=$(df -P "$mp" | awk 'NR==2 {gsub("%","",$5); print $5}')
    avail=$(df -Ph "$mp" | awk 'NR==2 {print $4}')
    msg="$mp at ${pct}% (${avail} free)"
    if [ "$pct" -ge "$CRIT_PCT" ]; then
        echo "CRITICAL: $msg" >&2
        logger -t apex-disk-watchdog -p daemon.err "CRITICAL: $msg"
        rc=2
    elif [ "$pct" -ge "$WARN_PCT" ]; then
        echo "WARNING: $msg" >&2
        logger -t apex-disk-watchdog -p daemon.warning "WARNING: $msg"
        [ "$rc" -lt 1 ] && rc=1 || true
    else
        echo "OK: $msg"
    fi
done

# On WARN/CRIT, attach the usual suspects so triage starts with data.
if [ "$rc" -ne 0 ] && command -v docker >/dev/null 2>&1; then
    echo "--- docker system df ---" >&2
    docker system df 2>/dev/null >&2 || true
    echo "--- largest container writable layers ---" >&2
    docker ps -as --format '{{.Size}}\t{{.Names}}' 2>/dev/null | sort -hr | head -5 >&2 || true
    echo "--- scanner scratch dirs still in worker /tmp ---" >&2
    for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'worker' || true); do
        n=$(docker exec "$c" sh -c 'ls -1d /tmp/stereoscope-* /tmp/syft-cataloger-* 2>/dev/null | wc -l' 2>/dev/null || echo '?')
        echo "  $c: $n" >&2
    done
fi

exit "$rc"
