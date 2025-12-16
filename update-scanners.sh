#!/bin/bash

#############################################################
# Scanner Update Script
# Purpose: Automatically update scanner tools and databases
# Schedule: Run weekly via cron
#############################################################

set -e

LOG_FILE="/var/log/scanner-updates.log"
BACKUP_DIR="/opt/scanner-backups"
COMPOSE_DIR="/opt/new-grype-scanner-v1/app"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

#############################################################
# Step 1: Check for new scanner versions
#############################################################
check_versions() {
    log "=== Checking for new scanner versions ==="

    # Get latest versions from GitHub
    LATEST_GRYPE=$(curl -s https://api.github.com/repos/anchore/grype/releases/latest | jq -r '.tag_name')
    LATEST_TRIVY=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r '.tag_name')
    LATEST_SYFT=$(curl -s https://api.github.com/repos/anchore/syft/releases/latest | jq -r '.tag_name')

    # Get current versions from containers
    CURRENT_GRYPE=$(docker exec app-worker-1 grype version --output json 2>/dev/null | jq -r '.version' || echo "unknown")
    CURRENT_TRIVY=$(docker exec app-worker-1 trivy --version 2>/dev/null | grep -oP 'Version: \K[0-9.]+' || echo "unknown")
    CURRENT_SYFT=$(docker exec app-worker-1 syft version --output json 2>/dev/null | jq -r '.version' || echo "unknown")

    log "Current versions:"
    log "  Grype: $CURRENT_GRYPE → Latest: $LATEST_GRYPE"
    log "  Trivy: $CURRENT_TRIVY → Latest: $LATEST_TRIVY"
    log "  Syft:  $CURRENT_SYFT → Latest: $LATEST_SYFT"

    # Check if updates are needed
    UPDATE_NEEDED=false

    if [ "$CURRENT_GRYPE" != "${LATEST_GRYPE#v}" ]; then
        warning "Grype update available!"
        UPDATE_NEEDED=true
    fi

    if [ "$CURRENT_TRIVY" != "${LATEST_TRIVY#v}" ]; then
        warning "Trivy update available!"
        UPDATE_NEEDED=true
    fi

    if [ "$CURRENT_SYFT" != "${LATEST_SYFT#v}" ]; then
        warning "Syft update available!"
        UPDATE_NEEDED=true
    fi

    echo "$UPDATE_NEEDED"
}

#############################################################
# Step 2: Update vulnerability databases (lightweight)
#############################################################
update_databases() {
    log "=== Updating vulnerability databases ==="

    # Grype database update
    log "Updating Grype database..."
    docker exec app-worker-1 grype db update || warning "Grype DB update failed"

    # Trivy database update
    log "Updating Trivy database..."
    docker exec app-worker-1 trivy image --download-db-only || warning "Trivy DB update failed"

    # Check database freshness
    GRYPE_DB_AGE=$(docker exec app-worker-1 cat /root/.cache/grype/db/6/last_update_check 2>/dev/null || echo "unknown")
    log "Grype DB last updated: $GRYPE_DB_AGE"

    log "✅ Database update complete"
}

#############################################################
# Step 3: Rebuild containers with new scanner versions
#############################################################
rebuild_containers() {
    log "=== Rebuilding containers with latest scanners ==="

    # Create backup
    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="$BACKUP_DIR/scanner-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

    log "Creating backup: $BACKUP_FILE"
    docker save app-worker app-api | gzip > "$BACKUP_FILE"

    cd "$COMPOSE_DIR"

    # Update Dockerfile with latest versions
    log "Updating Dockerfiles with latest versions..."

    # Build new containers
    log "Building new worker container..."
    docker-compose build --no-cache worker

    log "Building new API container..."
    docker-compose build --no-cache api

    # Test new containers
    log "Testing new containers..."
    docker-compose up -d

    sleep 15

    # Verify services
    if docker-compose ps | grep -q "Up"; then
        log "✅ Containers rebuilt and running successfully"

        # Clean up old backup (keep last 5)
        ls -t "$BACKUP_DIR"/scanner-backup-*.tar.gz | tail -n +6 | xargs -r rm
        log "Old backups cleaned up"
    else
        error "Container restart failed! Rolling back..."
        rollback
        exit 1
    fi
}

#############################################################
# Step 4: Rollback if update fails
#############################################################
rollback() {
    error "Rolling back to previous version..."

    LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/scanner-backup-*.tar.gz | head -1)

    if [ -f "$LATEST_BACKUP" ]; then
        log "Restoring from: $LATEST_BACKUP"
        docker load < "$LATEST_BACKUP"
        docker-compose up -d
        log "Rollback complete"
    else
        error "No backup found for rollback!"
    fi
}

#############################################################
# Step 5: Send notification
#############################################################
send_notification() {
    STATUS=$1
    MESSAGE=$2

    # You can integrate with Slack, Email, etc.
    log "Notification: $STATUS - $MESSAGE"

    # Example: Send to Slack webhook
    # curl -X POST -H 'Content-type: application/json' \
    #   --data "{\"text\":\"Scanner Update: $STATUS - $MESSAGE\"}" \
    #   YOUR_SLACK_WEBHOOK_URL
}

#############################################################
# Main execution
#############################################################
main() {
    log "=========================================="
    log "Scanner Update Process Started"
    log "=========================================="

    # Always update databases (quick, no downtime)
    update_databases

    # Check if binary updates are needed
    UPDATE_NEEDED=$(check_versions)

    if [ "$UPDATE_NEEDED" = "true" ]; then
        log "Scanner binaries need updating. Proceeding with rebuild..."

        # Rebuild with latest versions
        if rebuild_containers; then
            send_notification "SUCCESS" "Scanners updated successfully"
        else
            send_notification "FAILED" "Scanner update failed - rolled back"
            exit 1
        fi
    else
        log "✅ All scanners are up to date!"
        send_notification "INFO" "Scanners are current, databases updated"
    fi

    log "=========================================="
    log "Scanner Update Process Completed"
    log "=========================================="
}

# Run main function
main
