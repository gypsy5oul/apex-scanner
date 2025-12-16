# ⚡ Quick Update Guide

## 🎯 TL;DR - Already Automated!

Your scanner system **automatically updates** vulnerability databases daily and scanner binaries weekly.

**No manual action required!** Just check logs occasionally.

---

## 📋 Quick Commands

### **Check System Health:**
```bash
/opt/new-grype-scanner-v1/check-scanner-health.sh
```

### **Update Databases (30 seconds, zero downtime):**
```bash
/opt/new-grype-scanner-v1/update-databases.sh
```

### **Update Everything (5 minutes, 2 min downtime):**
```bash
/opt/new-grype-scanner-v1/update-scanners.sh
```

### **View Logs:**
```bash
# Database updates
tail -f /var/log/scanner-db-updates.log

# Scanner updates
tail -f /var/log/scanner-updates.log
```

---

## 🔄 What Gets Updated Automatically

### **Daily at 2 AM (No Downtime):**
- ✅ Grype vulnerability database
- ✅ Trivy vulnerability database
- ✅ Scans continue running

### **Weekly on Sunday at 3 AM (2 min downtime):**
- ✅ Check for new Grype version
- ✅ Check for new Trivy version
- ✅ Check for new Syft version
- ✅ Rebuild if updates available
- ✅ Automatic rollback if fails

---

## 🚨 When to Manually Update

### **Update Databases Immediately:**
- 🔴 Major CVE announced (e.g., Log4Shell, Heartbleed)
- 🟡 Before scanning critical production images
- 🟡 Database age > 7 days

### **Update Scanner Binaries:**
- 🔴 Security vulnerability in scanner itself
- 🟡 Need new features
- 🟢 New major version released

---

## 📊 Understanding Database Age

```
Age < 2 days   →  ✅ Fresh (optimal)
Age 2-7 days   →  ⚠️  Acceptable
Age > 7 days   →  ❌ Stale (update now!)
```

---

## 🎯 Quick Decision Tree

```
Is database > 7 days old?
  YES → Run: update-databases.sh
  NO  → Continue

Is scanner version outdated?
  YES → Run: update-scanners.sh (or wait for Sunday 3 AM)
  NO  → Continue

Everything green in health check?
  YES → 🎉 You're all set!
  NO  → Check logs
```

---

## 🔍 Verification After Update

```bash
# 1. Check health
/opt/new-grype-scanner-v1/check-scanner-health.sh

# 2. Test scan
curl -X POST http://10.0.2.121:7070/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:latest"}'

# 3. Verify services
docker-compose ps
```

---

## 💡 Pro Tips

1. **Check health weekly:** Add to your routine
2. **Review logs monthly:** Ensure updates are working
3. **Monitor database age:** Should never exceed 7 days
4. **Test after updates:** Quick scan to verify

---

## 🆘 Emergency Update

If you need to update **RIGHT NOW** (e.g., zero-day exploit):

```bash
# 1. Update databases immediately (30 seconds)
/opt/new-grype-scanner-v1/update-databases.sh

# 2. Verify update
docker exec app-worker-1 stat /root/.cache/grype/db/6/vulnerability.db

# 3. Re-scan affected images
curl -X POST http://10.0.2.121:7070/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "YOUR_IMAGE"}'
```

---

## 📞 Support

**Health Check Not Working?**
```bash
docker-compose ps
docker-compose logs worker --tail 50
```

**Updates Failing?**
```bash
tail -100 /var/log/scanner-updates.log
```

**Need to Rollback?**
```bash
ls /opt/scanner-backups/
# Automatic rollback built-in to update-scanners.sh
```

---

**Remember: The system is fully automated. You only need to check logs and run health checks occasionally!** ✨
