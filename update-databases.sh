#!/bin/bash

#############################################################
# Vulnerability Database Update Script
# Purpose: Update scanner databases without rebuilding containers
# Schedule: Run daily via cron (zero downtime)
#############################################################

set -e

LOG_FILE="/var/log/scanner-db-updates.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== Database Update Started ==="

# Update Grype database
log "Updating Grype vulnerability database..."
docker exec app-worker-1 grype db update 2>&1 | tee -a "$LOG_FILE"

# Update Trivy database
log "Updating Trivy vulnerability database..."
docker exec app-worker-1 trivy image --download-db-only 2>&1 | tee -a "$LOG_FILE"

# Check database info
log "Checking database freshness..."
GRYPE_DB_DATE=$(docker exec app-worker-1 stat -c %y /root/.cache/grype/db/6/vulnerability.db 2>/dev/null | cut -d' ' -f1 || echo "unknown")
TRIVY_DB_DATE=$(docker exec app-worker-1 stat -c %y /root/.cache/trivy/db/trivy.db 2>/dev/null | cut -d' ' -f1 || echo "unknown")

log "Grype DB updated: $GRYPE_DB_DATE"
log "Trivy DB updated: $TRIVY_DB_DATE"

log "=== Database Update Completed Successfully ==="
