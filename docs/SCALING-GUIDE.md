# 🚀 Scaling Guide - High-Volume Scanner Architecture

## Overview

This guide explains how to scale your scanner system from **10-20 scans/hour** to **hundreds of scans per day** using horizontal scaling.

---

## 📊 Current vs Scaled Architecture

### **Current Setup (Single Instance):**
```
Capacity: 10-20 scans/hour (240-480/day)
API:      1 instance
Workers:  1 instance (1 scan at a time)
Redis:    1 instance
```

### **Scaled Setup (Recommended for 100s of scans/day):**
```
Capacity: 100-200 scans/hour (2400-4800/day)
API:      2 instances (load balanced)
Workers:  4-10 instances (8-20 concurrent scans)
Redis:    1 instance (with persistence)
NGINX:    Load balancer + rate limiting
Monitoring: Prometheus + Grafana
```

---

## 🎯 Scaling Tiers

### **Tier 1: Light Load (< 50 scans/day)**
```
Workers: 1-2
API:     1
Concurrent scans: 2-4
Cost: Low
```
**Use case:** Development, small teams

---

### **Tier 2: Medium Load (50-200 scans/day)**
```
Workers: 2-4
API:     1-2
Concurrent scans: 4-8
Cost: Medium
```
**Use case:** Mid-size teams, CI/CD integration

---

### **Tier 3: High Load (200-500 scans/day)**
```
Workers: 4-6
API:     2
Concurrent scans: 8-12
Cost: Medium-High
```
**Use case:** Large teams, multiple projects

---

### **Tier 4: Very High Load (500-2000 scans/day)**
```
Workers: 6-10
API:     2-3
Concurrent scans: 12-20
Cost: High
```
**Use case:** Enterprise, platform service

---

### **Tier 5: Extreme Load (> 2000 scans/day)**
```
Workers: 10-20 (auto-scaling)
API:     3-5 (auto-scaling)
Redis:   Cluster mode
Concurrent scans: 20-40
Cost: Very High
```
**Use case:** Public service, cloud platform

---

## 🔧 Implementation

### **Step 1: Deploy Scaled Architecture**

```bash
cd /opt/new-grype-scanner-v1

# Stop current setup
docker-compose down

# Start scaled setup
docker-compose -f docker-compose.scale.yml up -d

# Verify deployment
docker-compose -f docker-compose.scale.yml ps
```

**What gets deployed:**
- ✅ 2 API instances (load balanced)
- ✅ 4 Worker instances (8 concurrent scans)
- ✅ 1 Redis instance (optimized)
- ✅ 1 NGINX load balancer
- ✅ Prometheus + Grafana monitoring

---

### **Step 2: Scale Workers Dynamically**

```bash
# Check current status
./scale-workers.sh status

# Scale up (add 2 workers)
./scale-workers.sh up

# Scale up by specific amount
./scale-workers.sh up 4

# Scale down (remove 2 workers)
./scale-workers.sh down

# Auto-scale based on queue size
./scale-workers.sh auto
```

---

### **Step 3: Monitor Performance**

**Access Grafana Dashboard:**
```
http://10.0.2.121:3000
Username: admin
Password: admin
```

**Access Prometheus:**
```
http://10.0.2.121:9090
```

**Check NGINX stats:**
```
curl http://10.0.2.121:7070/nginx_status
```

---

## 📈 Capacity Planning

### **Scan Time Benchmarks:**

| Image Size | Scan Time | Scans/Hour (1 worker) |
|------------|-----------|----------------------|
| Small (< 100 MB) | 30-60s | 60-120 |
| Medium (100-500 MB) | 60-120s | 30-60 |
| Large (500 MB - 2 GB) | 2-5 min | 12-30 |
| Very Large (> 2 GB) | 5-10 min | 6-12 |

### **Worker Scaling Calculator:**

```
Daily scans needed: N
Average scan time: T minutes
Required workers: (N * T) / (24 * 60 * 0.8)

Example:
  500 scans/day, 2 min average
  = (500 * 2) / (24 * 60 * 0.8)
  = 1000 / 1152
  = 0.87 workers → Use 2 workers (with buffer)
```

---

## 🎛️ Auto-Scaling

### **Setup Auto-Scaling (Cron-based):**

```bash
# Add to crontab
crontab -e

# Auto-scale every 5 minutes
*/5 * * * * /opt/new-grype-scanner-v1/scale-workers.sh auto >> /var/log/scanner-autoscale.log 2>&1
```

### **Auto-Scaling Rules:**

```
Queue Size    → Workers
0-9 scans     → 2 workers (minimum)
10-29 scans   → 4 workers
30-59 scans   → 6 workers
60-99 scans   → 8 workers
100+ scans    → 10 workers (maximum)
```

---

## 🔄 Load Balancing

### **NGINX Configuration:**

**Load Balancing Algorithm:** Least connections
- Routes requests to least busy API instance
- Health checks every 10s
- Automatic failover

**Rate Limiting:**
- API endpoints: 10 requests/second per IP
- Scan endpoint: 5 scans/minute per IP
- Prevents abuse and ensures fair usage

---

## 💾 Redis Optimization

### **For High Volume:**

```bash
# Edit docker-compose.scale.yml
redis:
  command: redis-server --maxmemory 4gb --maxmemory-policy allkeys-lru

# Optional: Enable persistence
  volumes:
    - redis-data:/data
  command: redis-server --appendonly yes --maxmemory 4gb
```

### **Redis Tuning:**

```bash
# Inside Redis container
docker exec redis_cache redis-cli CONFIG SET maxmemory-policy allkeys-lru
docker exec redis_cache redis-cli CONFIG SET maxmemory 4gb
docker exec redis_cache redis-cli CONFIG SET tcp-backlog 511
```

---

## 🎯 Performance Optimization

### **1. Worker Concurrency**

```yaml
# In docker-compose.scale.yml
worker:
  environment:
    - CELERY_CONCURRENCY=2  # 2 tasks per worker
```

**Rule of thumb:** `Concurrency = CPU cores per worker`

---

### **2. Scanner Database Caching**

```yaml
# Mount persistent cache
worker:
  volumes:
    - scanner-cache:/root/.cache
```

**Benefit:** Avoid re-downloading databases (saves ~30s per scan)

---

### **3. Image Registry Mirror**

```bash
# Setup local Docker registry mirror
docker run -d -p 5000:5000 \
  --name registry-mirror \
  -v /opt/registry:/var/lib/registry \
  registry:2
```

**Benefit:** Faster image pulls for repeated scans

---

### **4. Parallel SBOM Generation**

Already implemented! Grype, Trivy, and Syft run in parallel using ThreadPoolExecutor.

---

## 📊 Monitoring & Alerts

### **Key Metrics to Monitor:**

1. **Queue Length**
   ```bash
   docker exec redis_cache redis-cli LLEN celery
   ```

2. **Worker Utilization**
   ```bash
   docker-compose -f docker-compose.scale.yml ps worker
   ```

3. **Scan Success Rate**
   ```bash
   # Completed / Total
   docker exec redis_cache redis-cli DBSIZE
   ```

4. **Average Scan Time**
   ```bash
   docker-compose logs worker | grep "succeeded in" | tail -100
   ```

---

### **Alerting Rules:**

```
Queue > 50 for 10 min     → Scale up workers
Workers idle for 30 min   → Scale down workers
Scan failures > 10%       → Alert DevOps
Redis memory > 90%        → Scale Redis
API response time > 5s    → Check load balancer
```

---

## 🔒 Resource Limits

### **Per Component:**

```yaml
# API Container
resources:
  limits:
    cpus: '1'
    memory: 1G
  reservations:
    cpus: '0.5'
    memory: 512M

# Worker Container
resources:
  limits:
    cpus: '2'
    memory: 4G
  reservations:
    cpus: '1'
    memory: 2G
```

---

## 💰 Cost Optimization

### **Strategies:**

1. **Auto-Scaling**
   - Scale up during business hours
   - Scale down at night
   - Use minimum 2 workers

2. **Spot Instances (Cloud)**
   - Use spot/preemptible VMs for workers
   - Save 60-90% on worker costs
   - API on stable instances

3. **Database Sharing**
   - Workers share scanner databases
   - Saves bandwidth and storage

4. **Result Caching**
   - Cache scan results for 24 hours
   - Avoid rescanning same image

---

## 🚀 Deployment Strategies

### **Blue-Green Deployment:**

```bash
# Deploy new version (green)
docker-compose -f docker-compose.scale.yml pull
docker-compose -f docker-compose.scale.yml up -d --scale worker=8

# Test new version
curl http://10.0.2.121:7070/

# If OK, old version auto-replaced
# If failed, rollback
docker-compose -f docker-compose.scale.yml down
docker-compose up -d
```

---

### **Rolling Update:**

```bash
# Update workers one at a time
for i in {1..4}; do
  docker-compose -f docker-compose.scale.yml up -d --scale worker=$i
  sleep 30
done
```

---

## 🐛 Troubleshooting

### **High Queue, Workers Idle:**

```bash
# Check worker logs
docker-compose -f docker-compose.scale.yml logs worker --tail 100

# Restart workers
docker-compose -f docker-compose.scale.yml restart worker
```

---

### **Load Balancer Not Routing:**

```bash
# Check NGINX logs
docker logs scanner_lb

# Test upstream
docker exec scanner_lb wget -O- http://api:8000/
```

---

### **Redis Out of Memory:**

```bash
# Check memory usage
docker exec redis_cache redis-cli INFO memory

# Increase max memory
docker exec redis_cache redis-cli CONFIG SET maxmemory 8gb

# Or flush old data
docker exec redis_cache redis-cli FLUSHDB
```

---

## 📋 Quick Commands

### **Status & Monitoring:**

```bash
# Cluster status
./scale-workers.sh status

# Queue size
docker exec redis_cache redis-cli LLEN celery

# Worker count
docker-compose -f docker-compose.scale.yml ps worker | grep -c Up

# API health
curl http://10.0.2.121:7070/health
```

---

### **Scaling:**

```bash
# Scale to 6 workers
docker-compose -f docker-compose.scale.yml up -d --scale worker=6

# Scale to 3 APIs
docker-compose -f docker-compose.scale.yml up -d --scale api=3

# Auto-scale
./scale-workers.sh auto
```

---

### **Logs:**

```bash
# All workers
docker-compose -f docker-compose.scale.yml logs -f worker

# Specific worker
docker logs app-worker-2 -f

# NGINX access log
docker logs scanner_lb -f
```

---

## 🎯 Best Practices

1. **Start Small, Scale Up**
   - Begin with 2-4 workers
   - Monitor queue and add workers as needed

2. **Use Auto-Scaling**
   - Set up cron job for automatic scaling
   - Saves resources during off-peak

3. **Monitor Continuously**
   - Use Grafana dashboards
   - Set up alerts

4. **Resource Planning**
   - 1 worker ≈ 2 CPU cores, 4GB RAM
   - Plan capacity based on daily scan volume

5. **Database Updates**
   - Schedule during low-traffic periods
   - Use rolling updates

---

## 📊 Scaling Decision Matrix

| Daily Scans | Workers | API | Concurrent | Cost |
|-------------|---------|-----|------------|------|
| < 50 | 1-2 | 1 | 2-4 | $ |
| 50-200 | 2-4 | 1-2 | 4-8 | $$ |
| 200-500 | 4-6 | 2 | 8-12 | $$$ |
| 500-1000 | 6-8 | 2-3 | 12-16 | $$$$ |
| 1000-2000 | 8-10 | 3 | 16-20 | $$$$$ |
| > 2000 | 10-20 | 3-5 | 20-40 | $$$$$$ |

---

## 🔗 Advanced Topics

### **Kubernetes Deployment**

For enterprise scale (1000s of scans/day), consider Kubernetes:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scanner-worker
spec:
  replicas: 4
  selector:
    matchLabels:
      app: scanner-worker
  template:
    metadata:
      labels:
        app: scanner-worker
    spec:
      containers:
      - name: worker
        image: scanner-worker:latest
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
          requests:
            cpu: "1"
            memory: "2Gi"
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: scanner-worker-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: scanner-worker
  minReplicas: 2
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

---

## 📚 Additional Resources

- **Docker Compose Scaling:** https://docs.docker.com/compose/reference/up/
- **Celery Scaling:** https://docs.celeryproject.org/en/stable/userguide/workers.html
- **NGINX Load Balancing:** https://nginx.org/en/docs/http/load_balancing.html
- **Redis Optimization:** https://redis.io/topics/memory-optimization

---

**Your scanner is now ready to handle hundreds of scans per day!** 🚀
