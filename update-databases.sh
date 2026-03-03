#!/bin/bash

#############################################################
# Vulnerability Database Update Script
# Purpose: Update scanner databases on ALL worker containers
# Schedule: Run daily via cron at 2 AM (zero downtime)
#############################################################

LOG_FILE="/var/log/scanner-db-updates.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== Database Update Started ==="

# Find all running worker containers
WORKERS=$(docker ps --format '{{.Names}}' | grep -E 'worker' | grep -v autoscaler)

if [ -z "$WORKERS" ]; then
    log "ERROR: No worker containers found!"
    exit 1
fi

FAILED=0

for worker in $WORKERS; do
    log "Updating Grype DB on $worker..."
    if docker exec "$worker" grype db update 2>&1 | tee -a "$LOG_FILE"; then
        log "  $worker grype: OK"
    else
        log "  $worker grype: FAILED"
        FAILED=$((FAILED + 1))
    fi

    log "Updating Trivy DB on $worker..."
    if docker exec "$worker" trivy image --download-db-only 2>&1 | tee -a "$LOG_FILE"; then
        log "  $worker trivy: OK"
    else
        log "  $worker trivy: FAILED"
        FAILED=$((FAILED + 1))
    fi

    log "Updating Trivy Java DB on $worker..."
    if docker exec "$worker" trivy image --download-java-db-only 2>&1 | tee -a "$LOG_FILE"; then
        log "  $worker trivy-java: OK"
    else
        log "  $worker trivy-java: FAILED"
        FAILED=$((FAILED + 1))
    fi
done

# Verify freshness on first worker
FIRST_WORKER=$(echo "$WORKERS" | head -1)
log "Checking DB status on $FIRST_WORKER..."
docker exec "$FIRST_WORKER" grype db status 2>&1 | tee -a "$LOG_FILE"

if [ $FAILED -gt 0 ]; then
    log "=== Database Update Completed with $FAILED failures ==="
    exit 1
else
    log "=== Database Update Completed Successfully ==="
fi
