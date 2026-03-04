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

# Grype DB update (required when major version changes)
if ! grype db check >/dev/null 2>&1; then
  echo "Grype DB needs update, updating..."
  grype db update || echo "WARNING: Grype DB update failed (will retry on first scan)"
else
  echo "Grype DB: OK"
fi

if [ "$#" -eq 0 ]; then
  set -- celery -A app.tasks.celery worker --loglevel=info
fi

# Run command as root to avoid bind-mount permission failures.
exec "$@"
