# 🔧 Scanner Maintenance Guide

## Overview

This guide explains how to keep your multi-scanner system up-to-date with the latest vulnerability databases and scanner versions.

---

## 🎯 Update Strategy

### **Two-Tier Update Approach:**

| Component | Update Frequency | Downtime | Script |
|-----------|-----------------|----------|--------|
| **Vulnerability Databases** | Daily (automated) | None | `update-databases.sh` |
| **Scanner Binaries** | Weekly (automated) | ~2 minutes | `update-scanners.sh` |

---

## 📋 Automated Updates (RECOMMENDED)

### **Already Configured:**

```bash
# View scheduled jobs
crontab -l

# Expected output:
# Daily DB updates:   2:00 AM (no downtime)
# Weekly scanner updates:  Sunday 3:00 AM
# Monthly log cleanup: 1st day at 4:00 AM
```

### **Monitor Logs:**

```bash
# Database updates
tail -f /var/log/scanner-db-updates.log

# Scanner binary updates
tail -f /var/log/scanner-updates.log
```

---

## 🔍 Manual Health Check

### **Check System Status:**

```bash
# Run health check
/opt/new-grype-scanner-v1/check-scanner-health.sh

# Expected output shows:
# ✅ Container status
# ✅ Scanner versions (current vs latest)
# ✅ Database freshness
# ✅ API health
# 💡 Recommendations
```

---

## 🔄 Manual Updates

### **1. Update Databases Only (Zero Downtime)**

```bash
# Takes ~30 seconds, no service interruption
/opt/new-grype-scanner-v1/update-databases.sh

# What it does:
# - Updates Grype vulnerability database
# - Updates Trivy vulnerability database
# - No container restart needed
# - Scans continue running
```

**When to run:**
- If database is > 7 days old
- After major CVE announcements (e.g., Log4Shell)
- Before critical scans

---

### **2. Update Scanner Binaries (2 minute downtime)**

```bash
# Takes ~5-10 minutes, brief service interruption
/opt/new-grype-scanner-v1/update-scanners.sh

# What it does:
# 1. Checks for new scanner versions on GitHub
# 2. Creates backup of current containers
# 3. Rebuilds containers with latest versions
# 4. Restarts services
# 5. Verifies functionality
# 6. Rolls back if issues detected
```

**When to run:**
- New scanner major versions released
- Security vulnerabilities in scanners themselves
- New features needed
- Weekly (automated on Sunday 3 AM)

---

## 🚨 Troubleshooting

### **Problem: Databases Not Updating**

```bash
# Check if containers are running
docker-compose ps

# Manually update databases
docker exec app-worker-1 grype db update
docker exec app-worker-1 trivy image --download-db-only

# Check database age
docker exec app-worker-1 stat /root/.cache/grype/db/6/vulnerability.db
docker exec app-worker-1 stat /root/.cache/trivy/db/trivy.db
```

---

### **Problem: Scanner Update Failed**

```bash
# Check update logs
tail -100 /var/log/scanner-updates.log

# Restore from backup (automatic rollback)
# Backups stored in: /opt/scanner-backups/

# Manual rollback:
BACKUP_FILE=$(ls -t /opt/scanner-backups/scanner-backup-*.tar.gz | head -1)
docker load < $BACKUP_FILE
docker-compose up -d
```

---

### **Problem: GitHub Rate Limit**

```bash
# Check GitHub API rate limit
curl -s https://api.github.com/rate_limit | jq

# If rate limited, wait or use authenticated requests:
# Add GitHub token to update-scanners.sh:
# curl -H "Authorization: token YOUR_GITHUB_TOKEN" ...
```

---

## 📊 Database Update Frequency

### **How Scanners Update:**

**Grype Database:**
- Updated by Anchore daily
- Contains ~50,000+ CVEs
- Automatic download on scan
- Cached for 24 hours

**Trivy Database:**
- Updated by Aqua Security multiple times daily
- Contains ~180,000+ vulnerabilities
- Includes NVD, GitHub Advisory, etc.
- Cached for 12 hours

**Syft Cataloging:**
- No database (uses heuristics)
- Version embedded in binary
- Update requires binary update

---

## 🎯 Best Practices

### **Daily Operations:**

1. **Automated DB Updates** ✅
   - Already scheduled at 2 AM
   - Zero downtime
   - No action needed

2. **Health Monitoring**
   ```bash
   # Run daily or integrate with monitoring
   /opt/new-grype-scanner-v1/check-scanner-health.sh
   ```

### **Weekly Operations:**

1. **Scanner Binary Check** ✅
   - Automated on Sunday 3 AM
   - Reviews and applies updates
   - Minimal downtime

2. **Review Update Logs**
   ```bash
   # Check if updates succeeded
   tail -50 /var/log/scanner-updates.log
   ```

### **Monthly Operations:**

1. **Backup Verification**
   ```bash
   # Verify backups exist
   ls -lh /opt/scanner-backups/

   # Keep last 5 backups (automatic cleanup)
   ```

2. **Performance Review**
   ```bash
   # Check scan times
   docker-compose logs worker | grep "succeeded in"
   ```

---

## 🔐 Database Locations

### **Inside Containers:**

```bash
# Grype database
/root/.cache/grype/db/6/vulnerability.db  (1.2 GB)

# Trivy database
/root/.cache/trivy/db/trivy.db  (800 MB)
/root/.cache/trivy/java-db/  (Java vulnerabilities)

# Syft cache
/root/.cache/syft/  (SBOM cache)
```

### **Persistence:**

Databases are stored **inside containers** and rebuilt on restart. This ensures:
- ✅ Clean state on updates
- ✅ No stale data
- ✅ Consistent behavior

For persistent databases (optional):
```yaml
# Add to docker-compose.yml
volumes:
  - scanner-db:/root/.cache

volumes:
  scanner-db:
```

---

## 📈 Version History Tracking

### **Check Current Versions:**

```bash
# Grype
docker exec app-worker-1 grype version

# Trivy
docker exec app-worker-1 trivy --version

# Syft
docker exec app-worker-1 syft version
```

### **Check Release Notes:**

- **Grype:** https://github.com/anchore/grype/releases
- **Trivy:** https://github.com/aquasecurity/trivy/releases
- **Syft:** https://github.com/anchore/syft/releases

---

## 🎛️ Configuration Options

### **Change Update Schedule:**

```bash
# Edit crontab
crontab -e

# Modify times:
# Databases: Change "0 2 * * *" to your preferred time
# Scanners:  Change "0 3 * * 0" to your preferred day/time
```

### **Disable Automated Updates:**

```bash
# Remove cron jobs
crontab -l | grep -v scanner | crontab -

# Or comment out specific jobs
crontab -e
# Add # before lines you want to disable
```

---

## 🚀 Force Immediate Update

### **Update Everything Now:**

```bash
# Full update (databases + scanners)
/opt/new-grype-scanner-v1/update-scanners.sh

# This will:
# 1. Update all databases
# 2. Check for scanner updates
# 3. Rebuild if needed
# 4. Restart services
# Expected time: 5-10 minutes
```

### **Database Update Only:**

```bash
# Quick update (30 seconds)
/opt/new-grype-scanner-v1/update-databases.sh
```

---

## 📞 Support & Monitoring

### **Integration with Monitoring:**

```bash
# Add to your monitoring system
/opt/new-grype-scanner-v1/check-scanner-health.sh

# Parse output for alerts:
# - Database age > 7 days → WARNING
# - Scanner version outdated → INFO
# - API not responding → CRITICAL
```

### **Slack Notifications:**

```bash
# Edit update-scanners.sh
# Uncomment and configure webhook in send_notification()

# Add your Slack webhook URL
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

---

## 📋 Quick Reference

| Task | Command | Time | Downtime |
|------|---------|------|----------|
| **Health Check** | `check-scanner-health.sh` | 5s | None |
| **Update DBs** | `update-databases.sh` | 30s | None |
| **Update Scanners** | `update-scanners.sh` | 5-10m | 2m |
| **View Logs** | `tail -f /var/log/scanner-*.log` | - | None |
| **Manual DB Update** | `docker exec app-worker-1 grype db update` | 10s | None |

---

## ✅ Maintenance Checklist

### **Daily:**
- [x] Automated database updates (2 AM)
- [ ] Check health status (optional)

### **Weekly:**
- [x] Automated scanner updates (Sunday 3 AM)
- [ ] Review update logs

### **Monthly:**
- [x] Automated log cleanup (1st day 4 AM)
- [ ] Verify backups
- [ ] Review scan metrics

---

## 🎯 Key Points

1. **Databases update automatically daily** - No action needed
2. **Scanners update automatically weekly** - Minimal downtime
3. **Health check script** - Run anytime to check status
4. **Automatic rollback** - Failed updates revert automatically
5. **Backups maintained** - Last 5 backups kept automatically

**Your system is configured for hands-off operation! Just monitor the logs occasionally.**

---

## 📚 Additional Resources

- **Grype Documentation:** https://github.com/anchore/grype
- **Trivy Documentation:** https://trivy.dev/
- **Syft Documentation:** https://github.com/anchore/syft
- **Vulnerability Databases:**
  - NVD: https://nvd.nist.gov/
  - GitHub Advisory: https://github.com/advisories
