#!/bin/sh
# Restore the bundled Postgres from a pg-backup dump.
#
#   ./scripts/pg_restore.sh                 # restore the NEWEST backup
#   ./scripts/pg_restore.sh apex-YYYYMMDD-HHMMSS.sql.gz
#
# Runs the gzipped SQL dump through psql in the apex_postgres container.
# The dumps use --clean --if-exists, so existing objects are dropped/recreated.
set -eu

PG_CONTAINER="${PG_CONTAINER:-apex_postgres}"
BACKUP_CONTAINER="${BACKUP_CONTAINER:-apex_pg_backup}"
PGUSER="${POSTGRES_USER:-apex}"
PGDATABASE="${POSTGRES_DB:-apex}"

file="${1:-}"
if [ -z "$file" ]; then
    file="$(docker exec "$BACKUP_CONTAINER" sh -c 'ls -1t /backups/apex-*.sql.gz 2>/dev/null | head -1')"
    [ -n "$file" ] || { echo "No backups found in /backups"; exit 1; }
    echo "Newest backup: $file"
else
    case "$file" in
        /*) : ;;                       # absolute path inside the container
        *)  file="/backups/$file" ;;
    esac
fi

printf 'Restore %s into %s/%s? This DROPS and recreates objects. [y/N] ' "$file" "$PG_CONTAINER" "$PGDATABASE"
read -r ans
[ "$ans" = "y" ] || { echo "Aborted."; exit 1; }

docker exec "$BACKUP_CONTAINER" sh -c "gunzip -c '$file'" \
    | docker exec -i "$PG_CONTAINER" psql -U "$PGUSER" -d "$PGDATABASE" -v ON_ERROR_STOP=1
echo "Restore complete."
