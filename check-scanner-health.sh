#!/bin/bash

#############################################################
# Scanner Health Check Script
# Purpose: Check scanner versions and database freshness
#############################################################

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

COMPOSE_DIR="/opt/new-grype-scanner-v1/app"
COMPOSE_FILE="$COMPOSE_DIR/docker-compose.yml"

# Load Redis password from .env if present
if [ -f "$COMPOSE_DIR/.env" ]; then
    REDIS_PASSWORD=$(grep -E '^REDIS_PASSWORD=' "$COMPOSE_DIR/.env" | cut -d'=' -f2- | tr -d '"'\''\r')
fi

# Detect active worker container
WORKER_CONTAINER=""
for candidate in app-worker-system-1 app-worker-high-1 app-worker-batch-1; do
    if docker ps --format '{{.Names}}' | grep -q "^${candidate}$"; then
        WORKER_CONTAINER="$candidate"
        break
    fi
done

echo "=========================================="
echo "  Scanner Health Check"
echo "=========================================="
echo ""

#############################################################
# Check if containers are running
#############################################################
echo "📦 Container Status:"
COMPOSE_BIN="docker-compose"
if ! command -v docker-compose &>/dev/null; then
    COMPOSE_BIN="docker compose"
fi

if $COMPOSE_BIN -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "Up"; then
    echo -e "  ${GREEN}✅ All containers running${NC}"
else
    echo -e "  ${RED}❌ Some containers are down${NC}"
    $COMPOSE_BIN -f "$COMPOSE_FILE" ps
fi
echo ""

#############################################################
# Check scanner versions
#############################################################
echo "🔧 Scanner Versions:"

if [ -z "$WORKER_CONTAINER" ]; then
    echo -e "  ${RED}❌ No active worker container found${NC}"
else
    # Grype
    GRYPE_VERSION=$(docker exec "$WORKER_CONTAINER" grype version --output json 2>/dev/null | jq -r '.version' || echo "error")
    LATEST_GRYPE=$(curl -s https://api.github.com/repos/anchore/grype/releases/latest | jq -r '.tag_name' 2>/dev/null | sed 's/v//' || echo "")

    if [ -n "$LATEST_GRYPE" ] && [ "$GRYPE_VERSION" = "$LATEST_GRYPE" ]; then
        echo -e "  Grype:  ${GREEN}$GRYPE_VERSION (latest)${NC}"
    elif [ -n "$LATEST_GRYPE" ]; then
        echo -e "  Grype:  ${YELLOW}$GRYPE_VERSION (latest: $LATEST_GRYPE)${NC}"
    else
        echo -e "  Grype:  ${GREEN}$GRYPE_VERSION${NC}"
    fi

    # Trivy
    TRIVY_VERSION=$(docker exec "$WORKER_CONTAINER" trivy --version 2>/dev/null | grep -oP 'Version: \K[0-9.]+' | head -n1 || echo "error")
    LATEST_TRIVY=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r '.tag_name' 2>/dev/null | sed 's/v//' || echo "")

    if [ -n "$LATEST_TRIVY" ] && [ "$TRIVY_VERSION" = "$LATEST_TRIVY" ]; then
        echo -e "  Trivy:  ${GREEN}$TRIVY_VERSION (latest)${NC}"
    elif [ -n "$LATEST_TRIVY" ]; then
        echo -e "  Trivy:  ${YELLOW}$TRIVY_VERSION (latest: $LATEST_TRIVY)${NC}"
    else
        echo -e "  Trivy:  ${GREEN}$TRIVY_VERSION${NC}"
    fi

    # Syft
    SYFT_VERSION=$(docker exec "$WORKER_CONTAINER" syft version --output json 2>/dev/null | jq -r '.version' || echo "error")
    LATEST_SYFT=$(curl -s https://api.github.com/repos/anchore/syft/releases/latest | jq -r '.tag_name' 2>/dev/null | sed 's/v//' || echo "")

    if [ -n "$LATEST_SYFT" ] && [ "$SYFT_VERSION" = "$LATEST_SYFT" ]; then
        echo -e "  Syft:   ${GREEN}$SYFT_VERSION (latest)${NC}"
    elif [ -n "$LATEST_SYFT" ]; then
        echo -e "  Syft:   ${YELLOW}$SYFT_VERSION (latest: $LATEST_SYFT)${NC}"
    else
        echo -e "  Syft:   ${GREEN}$SYFT_VERSION${NC}"
    fi
fi

echo ""

#############################################################
# Check database freshness
#############################################################
echo "🗄️  Vulnerability Database Status:"

if [ -n "$WORKER_CONTAINER" ]; then
    # Grype DB
    GRYPE_DB_PATH="/home/scanner/.cache/grype/db/6/vulnerability.db"
    if docker exec "$WORKER_CONTAINER" test -f "$GRYPE_DB_PATH" 2>/dev/null; then
        GRYPE_DB_DATE=$(docker exec "$WORKER_CONTAINER" stat -c %y "$GRYPE_DB_PATH" 2>/dev/null | cut -d' ' -f1)
        GRYPE_DB_SIZE=$(docker exec "$WORKER_CONTAINER" du -h "$GRYPE_DB_PATH" 2>/dev/null | cut -f1)
        GRYPE_DB_EPOCH=$(docker exec "$WORKER_CONTAINER" stat -c %Y "$GRYPE_DB_PATH" 2>/dev/null || echo "0")
        NOW_EPOCH=$(date +%s)
        GRYPE_DB_AGE=$(( (NOW_EPOCH - GRYPE_DB_EPOCH) / 86400 ))

        if [ "$GRYPE_DB_AGE" -lt 2 ]; then
            echo -e "  Grype DB:  ${GREEN}✅ Fresh (${GRYPE_DB_AGE} days old, ${GRYPE_DB_SIZE})${NC}"
        elif [ "$GRYPE_DB_AGE" -lt 7 ]; then
            echo -e "  Grype DB:  ${YELLOW}⚠️  ${GRYPE_DB_AGE} days old (${GRYPE_DB_SIZE})${NC}"
        else
            echo -e "  Grype DB:  ${RED}❌ STALE (${GRYPE_DB_AGE} days old)${NC}"
        fi
        echo "             Last updated: $GRYPE_DB_DATE"
    else
        echo -e "  Grype DB:  ${RED}❌ Not found at $GRYPE_DB_PATH${NC}"
    fi

    # Trivy DB
    TRIVY_DB_PATH="/home/scanner/.cache/trivy/db/trivy.db"
    if docker exec "$WORKER_CONTAINER" test -f "$TRIVY_DB_PATH" 2>/dev/null; then
        TRIVY_DB_DATE=$(docker exec "$WORKER_CONTAINER" stat -c %y "$TRIVY_DB_PATH" 2>/dev/null | cut -d' ' -f1)
        TRIVY_DB_SIZE=$(docker exec "$WORKER_CONTAINER" du -h "$TRIVY_DB_PATH" 2>/dev/null | cut -f1)
        TRIVY_DB_EPOCH=$(docker exec "$WORKER_CONTAINER" stat -c %Y "$TRIVY_DB_PATH" 2>/dev/null || echo "0")
        NOW_EPOCH=$(date +%s)
        TRIVY_DB_AGE=$(( (NOW_EPOCH - TRIVY_DB_EPOCH) / 86400 ))

        if [ "$TRIVY_DB_AGE" -lt 2 ]; then
            echo -e "  Trivy DB:  ${GREEN}✅ Fresh (${TRIVY_DB_AGE} days old, ${TRIVY_DB_SIZE})${NC}"
        elif [ "$TRIVY_DB_AGE" -lt 7 ]; then
            echo -e "  Trivy DB:  ${YELLOW}⚠️  ${TRIVY_DB_AGE} days old (${TRIVY_DB_SIZE})${NC}"
        else
            echo -e "  Trivy DB:  ${RED}❌ STALE (${TRIVY_DB_AGE} days old)${NC}"
        fi
        echo "             Last updated: $TRIVY_DB_DATE"
    else
        echo -e "  Trivy DB:  ${RED}❌ Not found at $TRIVY_DB_PATH${NC}"
    fi
else
    echo -e "  ${RED}❌ Worker container not available to inspect DBs${NC}"
fi

echo ""

#############################################################
# Check API health
#############################################################
echo "🌐 API Status:"
API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:7070/health 2>/dev/null || echo "000")
if [ "$API_STATUS" = "200" ]; then
    echo -e "  ${GREEN}✅ API healthy (HTTP 200)${NC}"
    echo "     URL: http://127.0.0.1:7070/health"
else
    echo -e "  ${RED}❌ API not responding on http://127.0.0.1:7070/health (Status: $API_STATUS)${NC}"
fi

echo ""

#############################################################
# Check Redis activity
#############################################################
echo "📊 Recent Activity:"
REDIS_AUTH=""
if [ -n "$REDIS_PASSWORD" ]; then
    REDIS_AUTH="-a $REDIS_PASSWORD"
fi
SCAN_COUNT=$(docker exec redis_cache redis-cli $REDIS_AUTH DBSIZE 2>/dev/null | grep -oP '\d+' || echo "0")
echo "  Total keys in Redis: $SCAN_COUNT"

echo ""
echo "=========================================="
