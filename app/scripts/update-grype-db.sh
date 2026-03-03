#!/bin/bash
# Updates Grype vulnerability database on all worker containers
# Run via cron daily to prevent DB staleness (max age = 5 days)

LOG="/var/log/grype-db-update.log"
echo "=== Grype DB update started at $(date) ===" >> "$LOG"

WORKERS=$(docker ps --format '{{.Names}}' | grep -E 'worker')

for worker in $WORKERS; do
    echo "Updating $worker..." >> "$LOG"
    docker exec "$worker" grype db update >> "$LOG" 2>&1
    if [ $? -eq 0 ]; then
        echo "  $worker: OK" >> "$LOG"
    else
        echo "  $worker: FAILED" >> "$LOG"
    fi
done

echo "=== Grype DB update finished at $(date) ===" >> "$LOG"
echo "" >> "$LOG"
