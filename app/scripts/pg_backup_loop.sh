#!/bin/sh
# Phase 5: periodic pg_dump of the bundled Postgres, run by the pg-backup
# sidecar (postgres:16-alpine, which ships pg_dump). Writes gzipped plain-SQL
# dumps to /backups and prunes ones older than RETENTION_DAYS.
#
# Interim safety net: once the org's centralized Postgres takes over, that
# platform's own backup tooling supersedes this (see infra-future-migration).
set -eu

: "${PGHOST:=postgres}"
: "${PGUSER:=apex}"
: "${PGDATABASE:=apex}"
: "${BACKUP_DIR:=/backups}"
: "${BACKUP_INTERVAL:=86400}"   # seconds between dumps (default 24h)
: "${RETENTION_DAYS:=7}"

mkdir -p "$BACKUP_DIR"
echo "[pg-backup] started: host=$PGHOST db=$PGDATABASE interval=${BACKUP_INTERVAL}s retention=${RETENTION_DAYS}d"

while true; do
    ts="$(date +%Y%m%d-%H%M%S)"
    out="$BACKUP_DIR/apex-${ts}.sql.gz"
    echo "[pg-backup] $(date -u +%FT%TZ) dumping -> $out"
    # --clean --if-exists so the dump is self-contained and restorable onto a
    # populated DB; --no-owner so it restores under whatever role runs psql.
    if pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" --no-owner --clean --if-exists 2>/tmp/pgdump.err | gzip > "${out}.tmp"; then
        mv "${out}.tmp" "$out"
        echo "[pg-backup] ok: $(du -h "$out" | cut -f1) $out"
    else
        echo "[pg-backup] FAILED: $(cat /tmp/pgdump.err 2>/dev/null | tail -1)"
        rm -f "${out}.tmp"
    fi
    # Retention prune
    find "$BACKUP_DIR" -name 'apex-*.sql.gz' -type f -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
    echo "[pg-backup] sleeping ${BACKUP_INTERVAL}s ($(ls "$BACKUP_DIR"/apex-*.sql.gz 2>/dev/null | wc -l) backups retained)"
    sleep "$BACKUP_INTERVAL"
done
