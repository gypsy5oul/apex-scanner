"""
FastAPI application entry point with Prometheus metrics integration
"""
import json
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.routes import router
from app.routes_v2 import router_v2
from app.config import settings, get_redis_client
from app.auth import (
    validate_credentials_or_die, verify_token, validate_api_key, AUTH_COOKIE_NAME,
)
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

# Add CORS middleware - explicit origins only (no wildcard)
_cors_origins = settings.cors_origins_list
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    )
    logger.info("CORS enabled", origins=_cors_origins)
else:
    logger.warning("CORS_ORIGINS not set - CORS middleware disabled. Set CORS_ORIGINS for cross-origin access.")

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

# Reports & SBOMs are served behind authentication (previously public static
# mounts). Any AUTHENTICATED user may view any report/SBOM — so a shared report
# URL works for a colleague *after they log in*, but is not readable by the
# public. (Deliberately NOT per-tenant: reports are shareable among logged-in
# users.) Browsers without a session are redirected to /login; API clients
# (bearer / X-API-Key) get 401.
def _report_user(request: Request):
    """Resolve the caller from cookie, bearer, or API key — or None."""
    cookie_tok = request.cookies.get(AUTH_COOKIE_NAME)
    if cookie_tok and verify_token(cookie_tok):
        return True
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer ") and verify_token(authz[7:].strip()):
        return True
    api_key = request.headers.get("x-api-key")
    if api_key and settings.API_KEY_ENABLED and validate_api_key(api_key):
        return True
    return False


def _serve_protected(directory: str, filename: str, request: Request):
    if not _report_user(request):
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse(url="/login", status_code=302)
        raise HTTPException(status_code=401, detail="Authentication required")
    base = os.path.realpath(directory)
    full = os.path.realpath(os.path.join(base, filename))
    if full != base and not full.startswith(base + os.sep):
        raise HTTPException(status_code=404, detail="Not found")
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(full)


@app.get("/reports/{filename:path}", include_in_schema=False)
async def serve_report(filename: str, request: Request):
    return _serve_protected(settings.REPORTS_DIR, filename, request)


@app.get("/sboms/{filename:path}", include_in_schema=False)
async def serve_sbom(filename: str, request: Request):
    return _serve_protected(settings.SBOMS_DIR, filename, request)

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
    health_status = {
        "status": "healthy",
        "components": {}
    }

    # Check Redis connectivity
    try:
        r = get_redis_client()
        r.ping()
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


@app.get("/health/scanners", tags=["health"])
async def scanner_health():
    """
    Scanner health check — reads cached preflight results from workers.

    Returns per-scanner binary + DB status.
    Returns HTTP 503 if any enabled scanner is unavailable on all workers.
    Used by Kubernetes readiness probes and monitoring.
    """
    from fastapi.responses import JSONResponse

    r = get_redis_client()
    worker_keys = list(r.scan_iter("worker:health:*", count=100))

    workers = []
    for key in worker_keys:
        raw = r.get(key)
        if raw:
            try:
                workers.append(json.loads(raw))
            except json.JSONDecodeError:
                pass

    # Aggregate: a scanner is "available" if at least one worker reports it healthy
    scanner_names = ["grype", "trivy", "syft"]
    scanner_status = {}
    any_unhealthy = False

    for name in scanner_names:
        enabled = getattr(settings, f"ENABLE_{name.upper()}", False)
        if not enabled:
            scanner_status[name] = {"status": "disabled"}
            continue

        healthy_on = [
            w.get("hostname", "?")
            for w in workers
            if w.get(name, {}).get("status") == "healthy"
        ]
        unhealthy_errors = [
            w.get(name, {}).get("error", "unknown")
            for w in workers
            if w.get(name, {}).get("status") == "unhealthy"
        ]

        if healthy_on:
            scanner_status[name] = {
                "status": "healthy",
                "healthy_workers": healthy_on,
            }
        elif workers:
            any_unhealthy = True
            scanner_status[name] = {
                "status": "unhealthy",
                "errors": list(set(unhealthy_errors)),
            }
        else:
            any_unhealthy = True
            scanner_status[name] = {
                "status": "unknown",
                "error": "No worker health data available",
            }

    overall = "unhealthy" if any_unhealthy else "healthy"
    status_code = 503 if any_unhealthy else 200

    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall,
            "scanners": scanner_status,
            "workers_reporting": len(workers),
        },
    )


@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    # SECURITY: Refuse to start with insecure default credentials
    validate_credentials_or_die()

    logger.info(
        "Apex Scanner starting",
        version="3.0",
        scanners_enabled={
            "grype": settings.ENABLE_GRYPE,
            "trivy": settings.ENABLE_TRIVY,
            "syft": settings.ENABLE_SYFT
        }
    )

    # Phase 1: connect to Postgres (idle — no reads/writes yet). Non-fatal:
    # the app must keep running on Redis if the DB is unconfigured/unreachable.
    if settings.DATABASE_URL:
        try:
            from app.db.engine import ping as db_ping
            ok = await db_ping()
            logger.info("Postgres connection check", connected=ok)
        except Exception as e:
            logger.warning("Postgres not reachable at startup (continuing on Redis)", error=str(e))
    else:
        logger.info("Postgres not configured (DATABASE_URL empty) — DB layer dormant")


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    logger.info("Application shutting down")
    if settings.DATABASE_URL:
        try:
            from app.db.engine import dispose as db_dispose
            await db_dispose()
        except Exception:
            pass
