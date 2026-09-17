#!/bin/bash

#############################################################
# Dynamic Worker Scaling Script
# Usage: ./scale-workers.sh [up|down|auto|status] [number]
#############################################################

COMPOSE_DIR="/opt/new-grype-scanner-v1/app"
COMPOSE_FILE="$COMPOSE_DIR/docker-compose.yml"
REDIS_HOST="redis_cache"
SERVICE="worker-batch"

# Load Redis password from .env if present
if [ -f "$COMPOSE_DIR/.env" ]; then
    REDIS_PASSWORD=$(grep -E '^REDIS_PASSWORD=' "$COMPOSE_DIR/.env" | cut -d'=' -f2- | tr -d '"'\''\r')
fi

REDIS_AUTH=""
if [ -n "$REDIS_PASSWORD" ]; then
    REDIS_AUTH="-a $REDIS_PASSWORD"
fi

COMPOSE_BIN="docker-compose"
if ! command -v docker-compose &>/dev/null; then
    COMPOSE_BIN="docker compose"
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

#############################################################
# Get current queue size
#############################################################
get_queue_size() {
    local total=0
    for q in high_priority batch default low_priority system; do
        len=$(docker exec $REDIS_HOST redis-cli $REDIS_AUTH LLEN "$q" 2>/dev/null || echo "0")
        if [[ "$len" =~ ^[0-9]+$ ]]; then
            total=$((total + len))
        fi
    done
    echo "$total"
}

#############################################################
# Get current worker count
#############################################################
get_worker_count() {
    docker ps --format '{{.Names}}' | grep -c "^app-worker-batch" || echo "0"
}

#############################################################
# Scale workers to specific number
#############################################################
scale_to() {
    local target=$1
    log "Scaling $SERVICE workers to $target instances..."

    $COMPOSE_BIN -f "$COMPOSE_FILE" up -d --scale "${SERVICE}=$target" --no-recreate

    sleep 5

    actual=$(get_worker_count)
    log "Current batch worker count: $actual"

    if [ "$actual" -eq "$target" ]; then
        log "✅ Successfully scaled to $target workers"
    else
        error "Failed to scale. Current: $actual, Target: $target"
        return 1
    fi
}

#############################################################
# Auto-scale based on queue size
#############################################################
auto_scale() {
    log "Starting auto-scaling check..."

    queue_size=$(get_queue_size)
    current_workers=$(get_worker_count)

    log "Queue size: $queue_size, Current batch workers: $current_workers"

    # Calculate desired workers based on queue
    # Rule: 1 worker per 10 queued tasks, min 2, max 10
    if [ "$queue_size" -eq 0 ]; then
        desired_workers=2
    elif [ "$queue_size" -lt 10 ]; then
        desired_workers=2
    elif [ "$queue_size" -lt 30 ]; then
        desired_workers=4
    elif [ "$queue_size" -lt 60 ]; then
        desired_workers=6
    elif [ "$queue_size" -lt 100 ]; then
        desired_workers=8
    else
        desired_workers=10
    fi

    log "Desired workers: $desired_workers"

    if [ "$desired_workers" -ne "$current_workers" ]; then
        log "Scaling from $current_workers to $desired_workers workers"
        scale_to $desired_workers
    else
        log "No scaling needed"
    fi
}

#############################################################
# Show current status
#############################################################
show_status() {
    echo "=========================================="
    echo "  Scanner Cluster Status"
    echo "=========================================="
    echo ""

    # Queue status
    queue_size=$(get_queue_size)
    echo "📊 Queue Status:"
    echo "   Pending tasks across queues: $queue_size"
    echo ""

    # Worker status
    batch_workers=$(get_worker_count)
    high_workers=$(docker ps --format '{{.Names}}' | grep -c "^app-worker-high" || echo "0")
    echo "⚙️  Workers:"
    echo "   High-priority workers: $high_workers"
    echo "   Batch workers: $batch_workers"
    echo ""

    # API status
    api_status=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:7070/health 2>/dev/null || echo "000")
    echo "🌐 API Server:"
    if [ "$api_status" = "200" ]; then
        echo "   Status: Healthy (HTTP 200)"
    else
        echo "   Status: Unhealthy (HTTP $api_status)"
    fi
    echo ""

    # Redis status
    redis_mem=$(docker exec $REDIS_HOST redis-cli $REDIS_AUTH INFO memory 2>/dev/null | grep "used_memory_human" | cut -d: -f2 | tr -d '\r')
    echo "💾 Redis:"
    echo "   Memory usage: $redis_mem"
    echo ""

    # Recommendation
    if [ "$queue_size" -gt 20 ] && [ "$batch_workers" -lt 6 ]; then
        warning "High queue detected! Recommend scaling up batch workers."
        echo "   Run: $0 up"
    elif [ "$queue_size" -eq 0 ] && [ "$batch_workers" -gt 2 ]; then
        warning "Queue empty. Consider scaling down to save resources."
        echo "   Run: $0 down"
    else
        log "✅ System load is optimal"
    fi

    echo "=========================================="
}

#############################################################
# Main script
#############################################################
case "$1" in
    up)
        current=$(get_worker_count)
        new_count=$(($current + ${2:-2}))
        if [ "$new_count" -gt 10 ]; then
            new_count=10
            warning "Maximum 10 workers allowed"
        fi
        scale_to $new_count
        ;;

    down)
        current=$(get_worker_count)
        new_count=$(($current - ${2:-2}))
        if [ "$new_count" -lt 2 ]; then
            new_count=2
            warning "Minimum 2 workers required"
        fi
        scale_to $new_count
        ;;

    auto)
        auto_scale
        ;;

    status)
        show_status
        ;;

    *)
        echo "Usage: $0 {up|down|auto|status} [number]"
        echo ""
        echo "Examples:"
        echo "  $0 status        - Show current status"
        echo "  $0 up            - Add 2 batch workers"
        echo "  $0 up 4          - Add 4 batch workers"
        echo "  $0 down          - Remove 2 batch workers"
        echo "  $0 down 2        - Remove 2 batch workers"
        echo "  $0 auto          - Auto-scale based on queue"
        echo ""
        exit 1
        ;;
esac
