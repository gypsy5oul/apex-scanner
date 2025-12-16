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

echo "=========================================="
echo "  Scanner Health Check"
echo "=========================================="
echo ""

#############################################################
# Check if containers are running
#############################################################
echo "📦 Container Status:"
if docker-compose ps | grep -q "Up"; then
    echo -e "  ${GREEN}✅ All containers running${NC}"
else
    echo -e "  ${RED}❌ Some containers are down${NC}"
    docker-compose ps
fi
echo ""

#############################################################
# Check scanner versions
#############################################################
echo "🔧 Scanner Versions:"

# Grype
GRYPE_VERSION=$(docker exec app-worker-1 grype version --output json 2>/dev/null | jq -r '.version' || echo "error")
LATEST_GRYPE=$(curl -s https://api.github.com/repos/anchore/grype/releases/latest | jq -r '.tag_name' | sed 's/v//')

if [ "$GRYPE_VERSION" = "$LATEST_GRYPE" ]; then
    echo -e "  Grype:  ${GREEN}$GRYPE_VERSION (latest)${NC}"
else
    echo -e "  Grype:  ${YELLOW}$GRYPE_VERSION (latest: $LATEST_GRYPE)${NC}"
fi

# Trivy
TRIVY_VERSION=$(docker exec app-worker-1 trivy --version 2>/dev/null | grep -oP 'Version: \K[0-9.]+' || echo "error")
LATEST_TRIVY=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r '.tag_name' | sed 's/v//')

if [ "$TRIVY_VERSION" = "$LATEST_TRIVY" ]; then
    echo -e "  Trivy:  ${GREEN}$TRIVY_VERSION (latest)${NC}"
else
    echo -e "  Trivy:  ${YELLOW}$TRIVY_VERSION (latest: $LATEST_TRIVY)${NC}"
fi

# Syft
SYFT_VERSION=$(docker exec app-worker-1 syft version --output json 2>/dev/null | jq -r '.version' || echo "error")
LATEST_SYFT=$(curl -s https://api.github.com/repos/anchore/syft/releases/latest | jq -r '.tag_name' | sed 's/v//')

if [ "$SYFT_VERSION" = "$LATEST_SYFT" ]; then
    echo -e "  Syft:   ${GREEN}$SYFT_VERSION (latest)${NC}"
else
    echo -e "  Syft:   ${YELLOW}$SYFT_VERSION (latest: $LATEST_SYFT)${NC}"
fi

echo ""

#############################################################
# Check database freshness
#############################################################
echo "🗄️  Vulnerability Database Status:"

# Grype DB
if docker exec app-worker-1 test -f /root/.cache/grype/db/6/vulnerability.db 2>/dev/null; then
    GRYPE_DB_DATE=$(docker exec app-worker-1 stat -c %y /root/.cache/grype/db/6/vulnerability.db 2>/dev/null | cut -d' ' -f1)
    GRYPE_DB_SIZE=$(docker exec app-worker-1 du -h /root/.cache/grype/db/6/vulnerability.db 2>/dev/null | cut -f1)
    GRYPE_DB_AGE=$(( ($(date +%s) - $(docker exec app-worker-1 stat -c %Y /root/.cache/grype/db/6/vulnerability.db 2>/dev/null)) / 86400 ))

    if [ "$GRYPE_DB_AGE" -lt 2 ]; then
        echo -e "  Grype DB:  ${GREEN}✅ Fresh (${GRYPE_DB_AGE} days old, ${GRYPE_DB_SIZE})${NC}"
    elif [ "$GRYPE_DB_AGE" -lt 7 ]; then
        echo -e "  Grype DB:  ${YELLOW}⚠️  ${GRYPE_DB_AGE} days old (${GRYPE_DB_SIZE})${NC}"
    else
        echo -e "  Grype DB:  ${RED}❌ STALE (${GRYPE_DB_AGE} days old)${NC}"
    fi
    echo "             Last updated: $GRYPE_DB_DATE"
else
    echo -e "  Grype DB:  ${RED}❌ Not found${NC}"
fi

# Trivy DB
if docker exec app-worker-1 test -f /root/.cache/trivy/db/trivy.db 2>/dev/null; then
    TRIVY_DB_DATE=$(docker exec app-worker-1 stat -c %y /root/.cache/trivy/db/trivy.db 2>/dev/null | cut -d' ' -f1)
    TRIVY_DB_SIZE=$(docker exec app-worker-1 du -h /root/.cache/trivy/db/trivy.db 2>/dev/null | cut -f1)
    TRIVY_DB_AGE=$(( ($(date +%s) - $(docker exec app-worker-1 stat -c %Y /root/.cache/trivy/db/trivy.db 2>/dev/null)) / 86400 ))

    if [ "$TRIVY_DB_AGE" -lt 2 ]; then
        echo -e "  Trivy DB:  ${GREEN}✅ Fresh (${TRIVY_DB_AGE} days old, ${TRIVY_DB_SIZE})${NC}"
    elif [ "$TRIVY_DB_AGE" -lt 7 ]; then
        echo -e "  Trivy DB:  ${YELLOW}⚠️  ${TRIVY_DB_AGE} days old (${TRIVY_DB_SIZE})${NC}"
    else
        echo -e "  Trivy DB:  ${RED}❌ STALE (${TRIVY_DB_AGE} days old)${NC}"
    fi
    echo "             Last updated: $TRIVY_DB_DATE"
else
    echo -e "  Trivy DB:  ${RED}❌ Not found${NC}"
fi

echo ""

#############################################################
# Check API health
#############################################################
echo "🌐 API Status:"
API_RESPONSE=$(curl -s http://10.0.2.121:7070/ || echo "error")
if echo "$API_RESPONSE" | grep -q "Multi-Scanner"; then
    echo -e "  ${GREEN}✅ API responding${NC}"
    echo "     URL: http://10.0.2.121:7070"
else
    echo -e "  ${RED}❌ API not responding${NC}"
fi

echo ""

#############################################################
# Check recent scans
#############################################################
echo "📊 Recent Activity:"
SCAN_COUNT=$(docker exec redis_cache redis-cli DBSIZE 2>/dev/null | grep -oP '\d+' || echo "0")
echo "  Total scans in database: $SCAN_COUNT"

echo ""

#############################################################
# Recommendations
#############################################################
echo "💡 Recommendations:"

if [ "$GRYPE_VERSION" != "$LATEST_GRYPE" ]; then
    echo "  • Update Grype: Run /opt/new-grype-scanner-v1/update-scanners.sh"
fi

if [ "$TRIVY_VERSION" != "$LATEST_TRIVY" ]; then
    echo "  • Update Trivy: Run /opt/new-grype-scanner-v1/update-scanners.sh"
fi

if [ "$SYFT_VERSION" != "$LATEST_SYFT" ]; then
    echo "  • Update Syft: Run /opt/new-grype-scanner-v1/update-scanners.sh"
fi

if [ "$GRYPE_DB_AGE" -gt 7 ] || [ "$TRIVY_DB_AGE" -gt 7 ]; then
    echo "  • Update databases: Run /opt/new-grype-scanner-v1/update-databases.sh"
fi

if [ "$GRYPE_VERSION" = "$LATEST_GRYPE" ] && [ "$TRIVY_VERSION" = "$LATEST_TRIVY" ] && [ "$GRYPE_DB_AGE" -lt 2 ] && [ "$TRIVY_DB_AGE" -lt 2 ]; then
    echo -e "  ${GREEN}✅ Everything is up to date!${NC}"
fi

echo ""
echo "=========================================="
