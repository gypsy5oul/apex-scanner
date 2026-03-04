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

if [ "$#" -eq 0 ]; then
  set -- celery -A app.tasks.celery worker --loglevel=info
fi

# Keep HOME aligned with mounted Docker config path.
export HOME=/home/scanner

# Run command as root to avoid bind-mount permission failures.
exec "$@"
