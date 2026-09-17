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

# Only workers with WORKER_TYPE set (worker-high, worker-batch, worker-system)
# mount and utilize the scanner caches. Other services (autoscaler, flower, scheduler)
# do not run scans and must not download scanner DBs.
if [ -n "${WORKER_TYPE:-}" ]; then
  echo "Checking scanner databases for worker (${WORKER_TYPE})..."
  export HOME=/home/scanner
  export XDG_CACHE_HOME=/home/scanner/.cache
  export GRYPE_DB_CACHE_DIR=/home/scanner/.cache/grype/db
  export TRIVY_CACHE_DIR=/home/scanner/.cache/trivy

  # Scanner DBs are no longer baked into the image — they live in the shared
  # host-mounted cache (scanner-cache/{grype,trivy}). On a normal boot the
  # cache is already seeded, so these checks are fast no-ops. They only do a
  # real download when the shared cache is empty (fresh server / deleted dir),
  # in which case the first worker to start seeds it for all the others.

  # Grype DB — seed if missing. We check 'grype db status' rather than
  # 'grype db check' because 'check' queries the remote server and returns 100
  # whenever an upstream update is available, causing every worker on boot to
  # race-download the 2GB DB and leak orphaned grype-db-download* directories.
  # Scheduled updates are handled separately by worker-system.
  if ! grype db status >/dev/null 2>&1; then
    echo "Grype DB missing, downloading into shared cache..."
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
fi

if [ "$#" -eq 0 ]; then
  set -- celery -A app.tasks.celery worker --loglevel=info
fi

# Run command as root to avoid bind-mount permission failures.
exec "$@"
