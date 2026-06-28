# Postgres Backup & Restore (Phase 5)

The bundled Postgres (`apex_postgres`) is backed up by the **`pg-backup`** sidecar
(`postgres:16-alpine` running `scripts/pg_backup_loop.sh`).

> Interim safety net. Once the org's **centralized Postgres** takes over, its own
> backup tooling supersedes this — point `DATABASE_URL` at it and retire this
> sidecar (see the infra-future-migration note).

## What it does
- Runs `pg_dump --no-owner --clean --if-exists`, gzips it, and writes
  `apex-YYYYMMDD-HHMMSS.sql.gz` to the **`pg-backups`** volume (`/backups`).
- First dump runs at startup, then every `PG_BACKUP_INTERVAL` seconds (default 86400 = 24h).
- Prunes dumps older than `PG_BACKUP_RETENTION_DAYS` (default 7).

## Config (`app/.env`, all optional)
```
PG_BACKUP_INTERVAL=86400        # seconds between dumps
PG_BACKUP_RETENTION_DAYS=7      # keep this many days
```

## List backups
```sh
docker exec apex_pg_backup sh -c 'ls -lh /backups'
```

## Manual on-demand backup
```sh
docker exec apex_pg_backup sh -c \
  'pg_dump -h postgres -U "$PGUSER" -d "$PGDATABASE" --no-owner --clean --if-exists | gzip > /backups/apex-manual-$(date +%Y%m%d-%H%M%S).sql.gz'
```

## Restore
**Helper (from `app/`):**
```sh
./scripts/pg_restore.sh                      # restore the newest backup
./scripts/pg_restore.sh apex-20260628-090000.sql.gz
```

**Manual equivalent:**
```sh
docker exec apex_pg_backup sh -c 'gunzip -c /backups/<file>.sql.gz' \
  | docker exec -i apex_postgres psql -U apex -d apex -v ON_ERROR_STOP=1
```
The dumps are `--clean --if-exists`, so existing objects are dropped and recreated.

## Verify a restore (smoke)
```sh
docker exec apex_postgres psql -U apex -d apex -c \
  "SELECT 'scans='||count(*) FROM scans; SELECT 'vulns='||count(*) FROM vulnerabilities;"
```

## Copy a backup off-box (e.g. before a host rebuild)
```sh
docker run --rm -v app_pg-backups:/backups -v "$PWD":/out postgres:16-alpine \
  sh -c 'cp /backups/$(ls -1t /backups | head -1) /out/'
```

## Out of scope (future)
- **PG replication / HA** — a streaming replica or managed HA Postgres. The
  centralized Postgres will provide this; the bundled instance is single-node.
