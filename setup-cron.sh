#!/bin/bash

#############################################################
# Setup Automated Updates via Cron
#############################################################

echo "Setting up automated scanner updates..."

# Create log directory
mkdir -p /var/log
touch /var/log/scanner-db-updates.log
touch /var/log/scanner-updates.log

# Create cron jobs
cat > /tmp/scanner-cron << 'EOF'
# Scanner Maintenance Jobs

# Update vulnerability databases daily at 2 AM (zero downtime)
0 2 * * * /opt/new-grype-scanner-v1/update-databases.sh >> /var/log/scanner-db-updates.log 2>&1

# Check for scanner binary updates weekly on Sundays at 3 AM
0 3 * * 0 /opt/new-grype-scanner-v1/update-scanners.sh >> /var/log/scanner-updates.log 2>&1

# Clean old logs monthly
0 4 1 * * find /var/log -name "scanner-*.log" -mtime +30 -delete
EOF

# Install cron jobs
crontab -l > /tmp/current-cron 2>/dev/null || true
cat /tmp/current-cron /tmp/scanner-cron | crontab -
rm /tmp/scanner-cron /tmp/current-cron

echo "✅ Cron jobs installed successfully!"
echo ""
echo "Scheduled jobs:"
echo "  • Database updates: Daily at 2:00 AM (no downtime)"
echo "  • Scanner updates:  Weekly on Sunday at 3:00 AM"
echo "  • Log cleanup:      Monthly on 1st at 4:00 AM"
echo ""
echo "View scheduled jobs:"
echo "  crontab -l"
echo ""
echo "View logs:"
echo "  tail -f /var/log/scanner-db-updates.log"
echo "  tail -f /var/log/scanner-updates.log"
