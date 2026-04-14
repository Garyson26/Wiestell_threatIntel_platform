# 🚀 Celery Integration for SENTINEL Threat Intelligence Platform

Complete guide to deploying and using Celery for distributed feed processing.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Usage](#usage)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

This Celery integration solves the **Vercel/Render 300-second timeout issue** by offloading heavy feed processing to background workers.

### **Problem:**
- URLhaus feed has 56,000 records
- Processing takes 10+ minutes
- Vercel/Render kill requests after 300 seconds

### **Solution:**
- API queues task and returns immediately (~10ms)
- Celery workers process data in background
- Workers split feed into chunks (1000 records each)
- 56 workers process chunks in parallel
- **Total time: 2-3 minutes** (vs 10+ minutes synchronous)

---

## 🏗️ Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ POST /sync-celery/urlhaus
       v
┌─────────────────────────────────────────────┐
│           FastAPI (Vercel/Render)           │
│                                             │
│  1. Validate request                        │
│  2. Queue task to Redis                     │
│  3. Return task_id immediately              │
└──────────────────┬──────────────────────────┘
                   │ Task queued (~10ms)
                   v
         ┌─────────────────┐
         │  Redis (Broker) │
         └────────┬─────────┘
                  │ Workers poll for tasks
                  v
    ┌─────────────────────────────────┐
    │      Celery Workers (x8)        │
    │                                 │
    │  Worker 1: sync_feed_task       │
    │    ├─> Fetch URLhaus data       │
    │    ├─> Split into 56 chunks     │
    │    └─> Dispatch chunk tasks     │
    │                                 │
    │  Worker 2: process_chunk(1)     │
    │  Worker 3: process_chunk(2)     │
    │  Worker 4: process_chunk(3)     │
    │  ...                            │
    │  Worker 8: process_chunk(8)     │
    └────────────┬────────────────────┘
                 │ Bulk insert
                 v
         ┌───────────────┐
         │    MySQL DB   │
         └───────────────┘
```

---

## ⚡ Quick Start

### **1. Install Dependencies**

```bash
cd backend
pip install celery[redis] flower
```

### **2. Start Redis (Local)**

```bash
# Using Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Or using system package
redis-server
```

### **3. Start Celery Worker**

```bash
# Terminal 1: Start API
uvicorn app.main:app --reload

# Terminal 2: Start Celery worker
celery -A worker.celery_app worker --loglevel=info --concurrency=8

# Terminal 3 (Optional): Start Flower monitoring
celery -A worker.celery_app flower --port=5555
```

### **4. Test the System**

```bash
# Trigger feed sync
curl -X POST "http://localhost:8000/api/v1/feeds/sync-celery/urlhaus?force=true"

# Response:
{
  "message": "Feed sync task submitted successfully",
  "task_id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "feed_slug": "urlhaus",
  "status_url": "/api/v1/feeds/task-status/a1b2c3d4..."
}

# Check task status
curl "http://localhost:8000/api/v1/feeds/task-status/a1b2c3d4..."

# Response:
{
  "task_id": "a1b2c3d4...",
  "status": "SUCCESS",
  "result": {
    "feed_slug": "urlhaus",
    "total_records": 56000,
    "total_inserted": 55800,
    "duration_seconds": 145.3
  }
}
```

---

## 🚀 Deployment

### **Option 1: Deploy on Render (Recommended)**

Render supports background workers natively.

**1. Update `render.yaml`:**

```yaml
services:
  # Existing backend API
  - type: web
    name: wiestell-backend
    # ... existing config ...

  # NEW: Celery Worker
  - type: worker
    name: wiestell-celery-worker
    runtime: python
    buildCommand: pip install -r requirements.txt
    startCommand: celery -A worker.celery_app worker --loglevel=info --concurrency=8
    rootDir: backend
    envVars:
      - key: REDIS_URL
        fromService:
          name: wiestell-redis
          type: redis
          property: connectionString
      # ... copy other env vars from backend ...

  # Existing Redis
  - type: redis
    name: wiestell-redis
    # ... existing config ...
```

**2. Push to GitHub:**

```bash
git add .
git commit -m "Add Celery worker support"
git push
```

**3. Render will automatically:**
- Deploy the worker service
- Connect it to Redis
- Start processing tasks

---

### **Option 2: Deploy Workers Separately**

**Use case:** API on Vercel, Workers on separate server

**1. API (Vercel):**
- Deploy FastAPI as usual
- Set `REDIS_URL` to external Redis (Upstash, Redis Labs, etc.)

**2. Workers (AWS EC2, DigitalOcean, etc.):**

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export REDIS_URL="redis://your-redis-url:6379/0"
export DATABASE_URL="mysql+aiomysql://..."

# Start worker
celery -A worker.celery_app worker --loglevel=info --concurrency=8

# Use systemd for production (see deploy/celery-worker.service)
sudo systemctl start celery-worker
```

---

### **Option 3: Docker Deployment**

**`docker-compose.yml`:**

```yaml
version: '3.8'

services:
  api:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis

  celery-worker:
    build: ./backend
    command: celery -A worker.celery_app worker --loglevel=info --concurrency=8
    environment:
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

**Start:**

```bash
docker-compose up -d
```

---

## 📊 Monitoring

### **Option 1: Flower Web UI (Recommended)**

```bash
# Start Flower
celery -A worker.celery_app flower --port=5555

# Open in browser
http://localhost:5555
```

**Features:**
- Real-time task monitoring
- Worker status and statistics
- Task result inspection
- Rate limiting controls

---

### **Option 2: Command Line**

```bash
# Check active tasks
celery -A worker.celery_app inspect active

# Check registered tasks
celery -A worker.celery_app inspect registered

# Check worker stats
celery -A worker.celery_app inspect stats

# Check queue length
celery -A worker.celery_app inspect active_queues

# Ping workers
celery -A worker.celery_app inspect ping
```

---

### **Option 3: Logs**

```bash
# Worker logs show all task execution
celery -A worker.celery_app worker --loglevel=debug
```

---

## 🔧 Configuration

### **Worker Concurrency**

```bash
# Auto-detect CPU cores (default)
celery -A worker.celery_app worker

# Fixed concurrency (8 workers)
celery -A worker.celery_app worker --concurrency=8

# Autoscaling (min 2, max 10)
celery -A worker.celery_app worker --autoscale=10,2
```

### **Worker Pools**

```bash
# Prefork (multi-process, best for CPU-bound)
celery -A worker.celery_app worker --pool=prefork

# Gevent (coroutine-based, best for I/O-bound)
celery -A worker.celery_app worker --pool=gevent --concurrency=100

# Solo (single process, debugging)
celery -A worker.celery_app worker --pool=solo
```

### **Queue Routing**

```bash
# Process all queues (default)
celery -A worker.celery_app worker

# Process specific queue only
celery -A worker.celery_app worker --queues=high_priority

# Process multiple queues with priorities
celery -A worker.celery_app worker --queues=high_priority,default,low_priority
```

---

## 🐛 Troubleshooting

### **Issue: Workers Not Starting**

```bash
# Check Redis connection
redis-cli ping  # Should return "PONG"

# Check environment variables
echo $REDIS_URL

# Test Redis from Python
python -c "import redis; r=redis.from_url('redis://localhost:6379/0'); print(r.ping())"
```

### **Issue: Tasks Stuck in PENDING**

```bash
# Check if workers are running
celery -A worker.celery_app inspect active

# Check queue status
celery -A worker.celery_app inspect active_queues

# Restart workers
pkill -f "celery worker"
celery -A worker.celery_app worker --loglevel=info
```

### **Issue: Tasks Failing**

```bash
# Check worker logs
celery -A worker.celery_app worker --loglevel=debug

# Check task result in Redis
redis-cli GET celery-task-meta-{task_id}

# Retry failed task manually
from celery.result import AsyncResult
task = AsyncResult(task_id)
task.retry()
```

### **Issue: Memory Leak**

```bash
# Restart worker after N tasks (prevents memory leaks)
celery -A worker.celery_app worker --max-tasks-per-child=1000

# Monitor memory usage
celery -A worker.celery_app inspect stats | grep memory
```

---

## 📈 Performance Tuning

### **Large Feeds Optimization (56k+ records)**

```python
# Increase chunk size for fewer tasks
sync_feed_task.delay(feed_slug="urlhaus", chunk_size=2000)

# Use gevent pool for I/O-bound tasks
celery -A worker.celery_app worker --pool=gevent --concurrency=100
```

### **Rate Limiting**

```python
# In tasks.py
@celery_app.task(rate_limit="10/m")  # Max 10 tasks per minute
def rate_limited_task():
    pass
```

### **Task Prioritization**

```python
# High priority task (processed first)
sync_feed_task.apply_async(
    kwargs={"feed_slug": "urlhaus"},
    priority=9,  # 0-9, higher = higher priority
)
```

---

## 🎓 Next Steps

1. **Production Deployment:**
   - Update `render.yaml` to add worker service
   - Push to GitHub
   - Render will auto-deploy workers

2. **Monitoring Setup:**
   - Deploy Flower on separate service
   - Configure alerts for failed tasks
   - Set up metrics collection

3. **Optimization:**
   - Tune worker concurrency based on load
   - Implement task result cleanup
   - Add periodic tasks for scheduled syncs

4. **Integration:**
   - Update frontend to poll task status
   - Add WebSocket for real-time updates
   - Implement task cancellation

---

## 📚 Resources

- [Celery Documentation](https://docs.celeryq.dev/)
- [Redis Documentation](https://redis.io/docs/)
- [Flower Documentation](https://flower.readthedocs.io/)
- [Render Workers Guide](https://render.com/docs/background-workers)

---

**Questions? Issues?**

Check logs, read error messages, Google it! 🚀
