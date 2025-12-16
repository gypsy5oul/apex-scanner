"""
FastAPI application entry point with Prometheus metrics integration
"""
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.routes import router
from app.routes_v2 import router_v2
from app.config import settings
from app.logging_config import configure_logging, get_logger

# Configure structured logging
configure_logging(
    json_logs=(settings.LOG_FORMAT == "json"),
    log_level=settings.LOG_LEVEL
)
logger = get_logger(__name__)

# Create FastAPI application
app = FastAPI(
    title="Apex Scanner API",
    version="3.0",
    description="""
    # Apex Scanner - Peak Vulnerability Detection

    Enterprise-grade container security scanning platform with multi-scanner correlation.

    ## Core Features
    - Multi-scanner vulnerability detection (Grype + Trivy)
    - Cross-scanner validation with confidence scoring
    - EPSS scoring for exploitation probability
    - CISA KEV integration for active threats
    - SBOM generation (SPDX, CycloneDX, Syft)
    - Secret detection
    - Batch scanning
    - Scan comparison
    - Vulnerability search
    - Scan history & trends

    ## Enterprise Features
    - Scheduled scans with cron expressions
    - Risk-based prioritization
    - Quick wins remediation analysis
    - Base image tracking & comparison
    - Vulnerability trends analysis
    - PDF/CSV export
    - Executive summary reports
    - Real-time WebSocket progress updates
    - Prometheus metrics
    - Structured JSON logging

    ## Scanners
    - **Grype**: Vulnerability scanning
    - **Trivy**: Vulnerabilities + Secrets
    - **Syft**: SBOM generation
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup Prometheus metrics instrumentation
if settings.ENABLE_METRICS:
    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/metrics", "/health"],
        inprogress_name="http_requests_inprogress",
        inprogress_labels=True,
    )

    instrumentator.instrument(app).expose(app, endpoint=settings.METRICS_PATH, include_in_schema=True)

    logger.info("Prometheus metrics enabled", metrics_path=settings.METRICS_PATH)

# Ensure directories exist
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
os.makedirs(settings.SBOMS_DIR, exist_ok=True)

# Mount static file directories
if os.path.exists(settings.REPORTS_DIR):
    app.mount("/reports", StaticFiles(directory=settings.REPORTS_DIR), name="reports")
    logger.info("Mounted reports directory", path=settings.REPORTS_DIR)

if os.path.exists(settings.SBOMS_DIR):
    app.mount("/sboms", StaticFiles(directory=settings.SBOMS_DIR), name="sboms")
    logger.info("Mounted SBOMs directory", path=settings.SBOMS_DIR)

# Include API routers
app.include_router(router)
app.include_router(router_v2)


@app.get("/", tags=["health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "name": "Apex Scanner",
        "tagline": "Peak Vulnerability Detection",
        "message": "Apex Scanner API is running",
        "version": "3.0",
        "scanners": {
            "grype": {"enabled": settings.ENABLE_GRYPE, "purpose": "Vulnerability scanning"},
            "trivy": {"enabled": settings.ENABLE_TRIVY, "purpose": "Vulnerabilities + Secrets"},
            "syft": {"enabled": settings.ENABLE_SYFT, "purpose": "SBOM generation"}
        },
        "features": [
            "Multi-scanner vulnerability detection",
            "Cross-scanner validation & confidence scoring",
            "EPSS scoring for exploitation probability",
            "CISA KEV integration",
            "Secret detection",
            "SBOM generation (SPDX, CycloneDX)",
            "Risk-based prioritization",
            "Quick wins remediation",
            "Batch scanning",
            "Scan comparison",
            "Vulnerability search",
            "Scan history & trends",
            "Prometheus metrics"
        ],
        "endpoints": {
            "api_v1": "/api/v1",
            "api_v2": "/api/v2",
            "docs": "/docs",
            "metrics": settings.METRICS_PATH if settings.ENABLE_METRICS else None
        }
    }


@app.get("/health", tags=["health"])
async def detailed_health():
    """Detailed health check for monitoring"""
    import redis

    health_status = {
        "status": "healthy",
        "components": {}
    }

    # Check Redis connectivity
    try:
        redis_client = redis.Redis.from_url(settings.REDIS_URL)
        redis_client.ping()
        health_status["components"]["redis"] = {"status": "healthy"}
    except Exception as e:
        health_status["components"]["redis"] = {"status": "unhealthy", "error": str(e)}
        health_status["status"] = "degraded"

    # Check directories
    health_status["components"]["reports_dir"] = {
        "status": "healthy" if os.path.exists(settings.REPORTS_DIR) else "unhealthy",
        "path": settings.REPORTS_DIR
    }
    health_status["components"]["sboms_dir"] = {
        "status": "healthy" if os.path.exists(settings.SBOMS_DIR) else "unhealthy",
        "path": settings.SBOMS_DIR
    }

    return health_status


@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    logger.info(
        "Apex Scanner starting",
        version="3.0",
        scanners_enabled={
            "grype": settings.ENABLE_GRYPE,
            "trivy": settings.ENABLE_TRIVY,
            "syft": settings.ENABLE_SYFT
        }
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    logger.info("Application shutting down")
