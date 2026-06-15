#!/usr/bin/env bash
set -euo pipefail

REPORTS_DIR="${REPORTS_DIR:-/var/www/html/reports}"
SBOMS_DIR="${SBOMS_DIR:-/var/www/html/sboms}"
SCANNER_UID="${SCANNER_UID:-1000}"
SCANNER_GID="${SCANNER_GID:-1000}"

mkdir -p "$REPORTS_DIR" "$SBOMS_DIR" /home/scanner/.cache /home/scanner/.docker

# Host bind-mounts override image ownership. Repair ownership on every start.
chown -R "${SCANNER_UID}:${SCANNER_GID}" "$REPORTS_DIR" "$SBOMS_DIR" /home/scanner/.cache || true
chown "${SCANNER_UID}:${SCANNER_GID}" /home/scanner /home/scanner/.docker || true
chmod -R u+rwX,g+rwX "$REPORTS_DIR" "$SBOMS_DIR" || true

# Update scanner databases on startup (non-blocking, best-effort)
echo "Checking scanner databases..."
export HOME=/home/scanner
export XDG_CACHE_HOME=/home/scanner/.cache
export GRYPE_DB_CACHE_DIR=/home/scanner/.cache/grype/db
export TRIVY_CACHE_DIR=/home/scanner/.cache/trivy

# Scanner DBs are no longer baked into the image — they live in the shared
# host-mounted cache (scanner-cache/{grype,trivy}). On a normal boot the
# cache is already seeded, so these checks are fast no-ops. They only do a
# real download when the shared cache is empty (fresh server / deleted dir),
# in which case the first worker to start seeds it for all the others.

# Grype DB — seed if missing/stale.
if ! grype db check >/dev/null 2>&1; then
  echo "Grype DB missing or stale, downloading into shared cache..."
  grype db update || echo "WARNING: Grype DB update failed (will retry on first scan)"
else
  echo "Grype DB: OK"
fi

# Trivy DB — seed if the shared cache has no DB yet. Trivy has no cheap
# "check" command, so we test for the DB file directly and only download
# when it is absent.
if [ ! -f "${TRIVY_CACHE_DIR}/db/trivy.db" ]; then
  echo "Trivy DB missing, downloading into shared cache..."
  trivy image --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db:2 \
    || echo "WARNING: Trivy DB download failed (will retry on first scan)"
  trivy image --download-java-db-only --java-db-repository ghcr.io/aquasecurity/trivy-java-db:1 \
    || echo "WARNING: Trivy Java DB download failed (will retry on first scan)"
else
  echo "Trivy DB: OK"
fi

if [ "$#" -eq 0 ]; then
  set -- celery -A app.tasks.celery worker --loglevel=info
fi

# Run command as root to avoid bind-mount permission failures.
exec "$@"
