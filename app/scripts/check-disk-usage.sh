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
# Host side of the shared worker /tmp bind mount (see docker-compose.yml).
SCRATCH_DIR="${SCRATCH_DIR:-/opt/scanner-tmp}"

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
    # Order matters: `>&2` copies whatever fd2 currently is, so it must come
    # BEFORE `2>/dev/null` or stdout lands in /dev/null and this prints nothing.
    docker system df >&2 2>/dev/null || true
    echo "--- largest container writable layers ---" >&2
    docker ps -as --format '{{.Size}}\t{{.Names}}' 2>/dev/null | sort -hr | head -5 >&2 || true
fi

# Scanner scratch lives in one host dir shared by every worker, so count it
# here rather than per-container — `docker exec`ing each worker would report
# the same dirs N times over and overstate the leak.
if [ "$rc" -ne 0 ]; then
    echo "--- scanner scratch (shared worker /tmp) ---" >&2
    if [ -d "$SCRATCH_DIR" ]; then
        n=$(find "$SCRATCH_DIR" -maxdepth 1 \
            \( -name 'stereoscope-*' -o -name 'syft-cataloger-*' \) 2>/dev/null | wc -l)
        echo "  $SCRATCH_DIR: $n scratch dirs, $(du -sh "$SCRATCH_DIR" 2>/dev/null | cut -f1) total" >&2
    else
        echo "  $SCRATCH_DIR missing — workers are NOT sharing /tmp, so the" >&2
        echo "  cleanup task on the system queue cannot reach their scratch." >&2
    fi
fi

exit "$rc"
