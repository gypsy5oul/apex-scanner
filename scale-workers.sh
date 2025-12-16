#!/bin/bash

#############################################################
# Dynamic Worker Scaling Script
# Usage: ./scale-workers.sh [up|down|auto] [number]
#############################################################

COMPOSE_FILE="docker-compose.scale.yml"
REDIS_HOST="redis_cache"

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
    docker exec $REDIS_HOST redis-cli LLEN celery 2>/dev/null || echo "0"
}

#############################################################
# Get current worker count
#############################################################
get_worker_count() {
    docker-compose -f $COMPOSE_FILE ps worker 2>/dev/null | grep -c "Up" || echo "0"
}

#############################################################
# Scale workers to specific number
#############################################################
scale_to() {
    local target=$1
    log "Scaling workers to $target instances..."

    docker-compose -f $COMPOSE_FILE up -d --scale worker=$target

    sleep 5

    actual=$(get_worker_count)
    log "Current worker count: $actual"

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
    log "Starting auto-scaling..."

    queue_size=$(get_queue_size)
    current_workers=$(get_worker_count)

    log "Queue size: $queue_size, Current workers: $current_workers"

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
    echo "   Pending scans: $queue_size"
    echo ""

    # Worker status
    worker_count=$(get_worker_count)
    echo "⚙️  Workers:"
    echo "   Active workers: $worker_count"
    echo "   Capacity: $(($worker_count * 2)) concurrent scans"
    echo ""

    # API status
    api_count=$(docker-compose -f $COMPOSE_FILE ps api 2>/dev/null | grep -c "Up" || echo "0")
    echo "🌐 API Servers:"
    echo "   Active instances: $api_count"
    echo ""

    # Redis status
    redis_mem=$(docker exec $REDIS_HOST redis-cli INFO memory 2>/dev/null | grep "used_memory_human" | cut -d: -f2 | tr -d '\r')
    echo "💾 Redis:"
    echo "   Memory usage: $redis_mem"
    echo ""

    # Recent scan rate
    echo "📈 Performance:"
    completed_today=$(docker exec $REDIS_HOST redis-cli KEYS "*" 2>/dev/null | grep -c "^" || echo "0")
    echo "   Total scans: $completed_today"
    echo ""

    # Load recommendation
    if [ "$queue_size" -gt 20 ] && [ "$worker_count" -lt 6 ]; then
        warning "High queue detected! Recommend scaling up workers."
        echo "   Run: $0 up"
    elif [ "$queue_size" -eq 0 ] && [ "$worker_count" -gt 2 ]; then
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
        # Scale up
        current=$(get_worker_count)
        new_count=$(($current + ${2:-2}))
        if [ "$new_count" -gt 10 ]; then
            new_count=10
            warning "Maximum 10 workers allowed"
        fi
        scale_to $new_count
        ;;

    down)
        # Scale down
        current=$(get_worker_count)
        new_count=$(($current - ${2:-2}))
        if [ "$new_count" -lt 2 ]; then
            new_count=2
            warning "Minimum 2 workers required"
        fi
        scale_to $new_count
        ;;

    auto)
        # Auto-scale based on queue
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
        echo "  $0 up            - Add 2 workers"
        echo "  $0 up 4          - Add 4 workers"
        echo "  $0 down          - Remove 2 workers"
        echo "  $0 down 2        - Remove 2 workers"
        echo "  $0 auto          - Auto-scale based on queue"
        echo ""
        exit 1
        ;;
esac
