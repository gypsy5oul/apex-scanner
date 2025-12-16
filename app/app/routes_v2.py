"""
Enhanced API Routes v2 - Additional Endpoints
Includes scheduled scans, trends, exports, and WebSocket support
"""
import os
import json
import uuid
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Path, Body, WebSocket, WebSocketDisconnect, BackgroundTasks, Depends
from fastapi.responses import JSONResponse, StreamingResponse, Response
from pydantic import BaseModel, Field

from app.config import settings
from app.auth import (
    LoginRequest, LoginResponse, TokenData,
    login, get_current_admin, get_optional_admin
)
from app.logging_config import get_logger
from app.scheduler import ScheduleManager, GoogleChatNotifier
from app.base_image_tracker import BaseImageTracker
from app.cvss_enrichment import CVSSEnricher
from app.trends import TrendAnalyzer
from app.export import ReportExporter
from app.websocket_manager import manager, ScanProgressTracker, RedisPubSubManager
from app.enrichment import (
    VulnerabilityEnricher, KEVClient, EPSSClient, DigestCache,
    enrich_scan_results, update_kev_database
)

import redis

logger = get_logger(__name__)

# Redis connection
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=20,
    decode_responses=True
)


def get_redis_client() -> redis.Redis:
    return redis.Redis(connection_pool=redis_pool)


# Create router for v2 endpoints
router_v2 = APIRouter(prefix="/api/v2", tags=["enterprise"])


# ============== Authentication Endpoints ==============

@router_v2.post(
    "/auth/login",
    response_model=LoginResponse,
    summary="Admin Login",
    description="Authenticate as admin and receive JWT token",
    tags=["authentication"]
)
async def admin_login(request: LoginRequest = Body(...)):
    """
    Login with admin credentials to access protected endpoints.

    Protected endpoints include:
    - Scheduled scans management
    - Base image tracking
    - System status and updates
    - Worker monitoring
    """
    return login(request.username, request.password)


@router_v2.get(
    "/auth/verify",
    summary="Verify Token",
    description="Verify if the current token is valid",
    tags=["authentication"]
)
async def verify_auth(current_admin: TokenData = Depends(get_current_admin)):
    """Verify if the current JWT token is valid"""
    return {
        "valid": True,
        "username": current_admin.username,
        "expires": current_admin.exp.isoformat()
    }


@router_v2.get(
    "/auth/status",
    summary="Auth Status",
    description="Check authentication status (works without token)",
    tags=["authentication"]
)
async def auth_status(current_admin: Optional[TokenData] = Depends(get_optional_admin)):
    """Check if user is authenticated (doesn't require auth)"""
    if current_admin:
        return {
            "authenticated": True,
            "username": current_admin.username,
            "expires": current_admin.exp.isoformat()
        }
    return {
        "authenticated": False,
        "username": None,
        "expires": None
    }


# ============== Request/Response Models ==============

class ScheduleCreateRequest(BaseModel):
    """Request to create a scheduled scan"""
    name: str = Field(..., description="Schedule name", min_length=1, max_length=100)
    images: List[str] = Field(..., description="List of images to scan")
    cron_expression: str = Field(
        default="0 6 * * *",
        description="Cron expression (minute hour day month weekday)"
    )
    google_chat_webhook: Optional[str] = Field(None, description="Google Chat webhook URL")
    description: str = Field(default="", description="Schedule description")
    enabled: bool = Field(default=True, description="Whether schedule is enabled")


class BaseImageRegisterRequest(BaseModel):
    """Request to register a base image for tracking"""
    image_name: str = Field(..., description="Base image name (e.g., 'ubuntu')")
    image_tag: str = Field(..., description="Image tag (e.g., '22.04')")
    description: str = Field(default="", description="Description")


class ExportRequest(BaseModel):
    """Request for export operations"""
    scan_id: str = Field(..., description="Scan ID to export")
    format: str = Field(..., description="Export format: csv, pdf, executive_pdf")
    include_details: bool = Field(default=False, description="Include vulnerability details")


# ============== Scheduled Scans Endpoints ==============

@router_v2.post(
    "/schedules",
    summary="Create Scheduled Scan",
    description="Create a new scheduled scan with optional Google Chat notifications"
)
async def create_schedule(
    request: ScheduleCreateRequest = Body(...),
    admin: TokenData = Depends(get_current_admin)
):
    """Create a new scheduled scan (Admin only)"""
    try:
        manager = ScheduleManager()
        schedule = manager.create_schedule(
            name=request.name,
            images=request.images,
            cron_expression=request.cron_expression,
            google_chat_webhook=request.google_chat_webhook,
            enabled=request.enabled,
            description=request.description
        )

        logger.info(
            "Schedule created",
            name=request.name,
            image_count=len(request.images)
        )

        return JSONResponse({
            "status": "created",
            "schedule": schedule
        })

    except Exception as e:
        logger.error("Failed to create schedule", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router_v2.get(
    "/schedules",
    summary="List All Schedules",
    description="Get all configured scheduled scans"
)
async def list_schedules(admin: TokenData = Depends(get_current_admin)):
    """List all scheduled scans (Admin only)"""
    manager = ScheduleManager()
    schedules = manager.list_schedules()

    return {
        "total": len(schedules),
        "schedules": schedules
    }


@router_v2.get(
    "/schedules/{name}",
    summary="Get Schedule Details",
    description="Get details of a specific schedule"
)
async def get_schedule(
    name: str = Path(..., description="Schedule name"),
    admin: TokenData = Depends(get_current_admin)
):
    """Get schedule details (Admin only)"""
    manager = ScheduleManager()
    schedule = manager.get_schedule(name)

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return schedule


@router_v2.put(
    "/schedules/{name}",
    summary="Update Schedule",
    description="Update an existing schedule"
)
async def update_schedule(
    name: str = Path(..., description="Schedule name"),
    updates: Dict[str, Any] = Body(...),
    admin: TokenData = Depends(get_current_admin)
):
    """Update a schedule (Admin only)"""
    manager = ScheduleManager()
    schedule = manager.update_schedule(name, updates)

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return schedule


@router_v2.delete(
    "/schedules/{name}",
    summary="Delete Schedule",
    description="Delete a scheduled scan"
)
async def delete_schedule(
    name: str = Path(..., description="Schedule name"),
    admin: TokenData = Depends(get_current_admin)
):
    """Delete a schedule (Admin only)"""
    manager = ScheduleManager()
    deleted = manager.delete_schedule(name)

    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return {"status": "deleted", "name": name}


@router_v2.post(
    "/schedules/{name}/run",
    summary="Run Schedule Now",
    description="Manually trigger a scheduled scan"
)
async def run_schedule_now(
    name: str = Path(..., description="Schedule name"),
    admin: TokenData = Depends(get_current_admin)
):
    """Manually run a scheduled scan (Admin only)"""
    from app.tasks import scan_image

    mgr = ScheduleManager()
    schedule = mgr.get_schedule(name)

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    images = schedule.get("images", [])
    if isinstance(images, str):
        images = json.loads(images)

    scan_ids = []
    redis_client = get_redis_client()

    for image in images:
        scan_id = str(uuid.uuid4())
        scan_ids.append(scan_id)

        # Initialize scan
        redis_client.hset(scan_id, mapping={
            "status": "in_progress",
            "image_name": image,
            "schedule_name": name,
            "created_at": datetime.utcnow().isoformat()
        })
        redis_client.expire(scan_id, settings.SCAN_RESULT_TTL)

        # Track in image history index (for Recent Scans / History display)
        history_key = f"history:{image}"
        redis_client.lpush(history_key, scan_id)
        redis_client.ltrim(history_key, 0, 99)  # Keep last 100 scans per image
        redis_client.expire(history_key, settings.SCAN_RESULT_TTL)

        # Submit task
        scan_image.apply_async(args=[image, scan_id])

    return {
        "status": "triggered",
        "schedule_name": name,
        "scan_ids": scan_ids,
        "image_count": len(images)
    }


# ============== Base Image Tracking Endpoints ==============

@router_v2.post(
    "/base-images",
    summary="Register Base Image",
    description="Register a base image for vulnerability tracking"
)
async def register_base_image(
    request: BaseImageRegisterRequest = Body(...),
    admin: TokenData = Depends(get_current_admin)
):
    """Register a base image for tracking (Admin only)"""
    tracker = BaseImageTracker()
    result = tracker.register_base_image(
        request.image_name,
        request.image_tag,
        request.description
    )

    return {"status": "registered", "base_image": result}


@router_v2.get(
    "/base-images",
    summary="List Base Images",
    description="List all registered base images"
)
async def list_base_images(admin: TokenData = Depends(get_current_admin)):
    """List all registered base images (Admin only)"""
    tracker = BaseImageTracker()
    base_images = tracker.list_base_images()

    return {
        "total": len(base_images),
        "base_images": base_images
    }


@router_v2.get(
    "/base-images/history",
    summary="Get Base Image History",
    description="Get vulnerability history for a base image"
)
async def get_base_image_history(
    image_name: str = Query(..., description="Base image name"),
    tag: str = Query(..., description="Image tag"),
    limit: int = Query(30, ge=1, le=100),
    admin: TokenData = Depends(get_current_admin)
):
    """Get base image vulnerability history (Admin only)"""
    tracker = BaseImageTracker()
    history = tracker.get_base_image_history(image_name, tag, limit)

    return {
        "image": f"{image_name}:{tag}",
        "history": history
    }


@router_v2.get(
    "/base-images/compare",
    summary="Compare Base Images",
    description="Compare vulnerabilities between two base images"
)
async def compare_base_images(
    image1: str = Query(..., description="First image name"),
    tag1: str = Query(..., description="First image tag"),
    image2: str = Query(..., description="Second image name"),
    tag2: str = Query(..., description="Second image tag"),
    admin: TokenData = Depends(get_current_admin)
):
    """Compare two base images (Admin only)"""
    tracker = BaseImageTracker()
    comparison = tracker.compare_base_images(image1, tag1, image2, tag2)

    return comparison


@router_v2.post(
    "/base-images/scan-all",
    summary="Scan All Base Images",
    description="Trigger an immediate scan of all registered base images"
)
async def scan_all_base_images(
    background_tasks: BackgroundTasks,
    admin: TokenData = Depends(get_current_admin)
):
    """Trigger scan for all registered base images (Admin only)"""
    from app.tasks import scan_base_images

    tracker = BaseImageTracker()
    base_images = tracker.list_base_images()

    if not base_images:
        raise HTTPException(
            status_code=400,
            detail="No base images registered"
        )

    # Trigger the task asynchronously
    task = scan_base_images.apply_async()

    return {
        "status": "triggered",
        "task_id": task.id,
        "base_image_count": len(base_images),
        "message": f"Scanning {len(base_images)} base image(s)"
    }


@router_v2.put(
    "/base-images/update",
    summary="Update Base Image",
    description="Update a base image's description"
)
async def update_base_image(
    image_name: str = Query(..., description="Base image name"),
    tag: str = Query(..., description="Image tag"),
    request: dict = Body(...),
    admin: TokenData = Depends(get_current_admin)
):
    """Update a registered base image (Admin only)"""
    redis_client = get_redis_client()
    base_id = f"base:{image_name}:{tag}"

    if not redis_client.exists(base_id):
        raise HTTPException(
            status_code=404,
            detail=f"Base image {image_name}:{tag} not found"
        )

    # Update description if provided
    if "description" in request:
        redis_client.hset(base_id, "description", request["description"] or "")

    # Return updated data
    data = redis_client.hgetall(base_id)
    if "current_vulns" in data:
        import json
        data["current_vulns"] = json.loads(data["current_vulns"])
    if "scan_count" in data:
        data["scan_count"] = int(data["scan_count"])
    if data.get("last_scanned") == "":
        data["last_scanned"] = None

    return {
        "status": "updated",
        "base_image": data
    }


@router_v2.get(
    "/base-images/details",
    summary="Get Base Image Details",
    description="Get detailed information about a base image including scan history"
)
async def get_base_image_details(
    image_name: str = Query(..., description="Base image name"),
    tag: str = Query(..., description="Image tag"),
    admin: TokenData = Depends(get_current_admin)
):
    """Get detailed base image information with scan history (Admin only)"""
    import json
    redis_client = get_redis_client()
    base_id = f"base:{image_name}:{tag}"

    if not redis_client.exists(base_id):
        raise HTTPException(
            status_code=404,
            detail=f"Base image {image_name}:{tag} not found"
        )

    # Get base image data
    data = redis_client.hgetall(base_id)
    if "current_vulns" in data:
        data["current_vulns"] = json.loads(data["current_vulns"])
    if "scan_count" in data:
        data["scan_count"] = int(data["scan_count"])
    if data.get("last_scanned") == "":
        data["last_scanned"] = None

    # Get scan history
    history_key = f"base_history:{image_name}:{tag}"
    history_entries = redis_client.lrange(history_key, 0, 29)  # Last 30 scans
    history = [json.loads(entry) for entry in history_entries]

    # Get recent scan details
    recent_scans = []
    for entry in history[:10]:  # Last 10 scans with details
        scan_id = entry.get("scan_id")
        if scan_id:
            scan_data = redis_client.hgetall(scan_id)
            if scan_data:
                recent_scans.append({
                    "scan_id": scan_id,
                    "timestamp": entry.get("timestamp"),
                    "status": scan_data.get("status", "unknown"),
                    "critical": int(scan_data.get("critical", 0)),
                    "high": int(scan_data.get("high", 0)),
                    "medium": int(scan_data.get("medium", 0)),
                    "low": int(scan_data.get("low", 0)),
                    "fixable_critical": int(scan_data.get("fixable_critical", 0)),
                    "fixable_high": int(scan_data.get("fixable_high", 0)),
                    "fixable_medium": int(scan_data.get("fixable_medium", 0)),
                    "fixable_low": int(scan_data.get("fixable_low", 0)),
                    "total_packages": int(scan_data.get("total_packages", 0)),
                    "report_url": scan_data.get("report_url", ""),
                })

    # Calculate vulnerability trend
    vuln_trend = []
    for entry in history:
        vulns = entry.get("vulns", {})
        vuln_trend.append({
            "date": entry.get("timestamp", "")[:10],
            "critical": vulns.get("critical", 0),
            "high": vulns.get("high", 0),
            "medium": vulns.get("medium", 0),
            "low": vulns.get("low", 0),
        })

    # Calculate risk score (weighted)
    current_vulns = data.get("current_vulns", {})
    risk_score = (
        current_vulns.get("critical", 0) * 10 +
        current_vulns.get("high", 0) * 5 +
        current_vulns.get("medium", 0) * 2 +
        current_vulns.get("low", 0) * 1
    )

    return {
        "base_image": data,
        "recent_scans": recent_scans,
        "vulnerability_trend": vuln_trend[:30],  # Last 30 data points
        "risk_score": risk_score,
        "total_scans": len(history),
    }


@router_v2.delete(
    "/base-images/remove",
    summary="Delete Base Image",
    description="Remove a base image from tracking"
)
async def delete_base_image(
    image_name: str = Query(..., description="Base image name"),
    tag: str = Query(..., description="Image tag"),
    admin: TokenData = Depends(get_current_admin)
):
    """Delete a registered base image"""
    redis_client = get_redis_client()
    base_id = f"base:{image_name}:{tag}"

    if not redis_client.exists(base_id):
        raise HTTPException(
            status_code=404,
            detail=f"Base image {image_name}:{tag} not found"
        )

    redis_client.delete(base_id)
    redis_client.srem("tracked_base_images", base_id)

    # Also delete history
    history_key = f"base_history:{image_name}:{tag}"
    redis_client.delete(history_key)

    return {
        "status": "deleted",
        "image": f"{image_name}:{tag}"
    }


# ============== CVSS Enrichment Endpoints ==============

@router_v2.get(
    "/scan/{scan_id}/cvss",
    summary="Get CVSS Enriched Vulnerabilities",
    description="Get vulnerabilities with detailed CVSS scores and exploitability metrics"
)
async def get_cvss_enriched(
    scan_id: str = Path(..., description="Scan ID")
):
    """Get CVSS enriched vulnerability data"""
    redis_client = get_redis_client()

    vulns_raw = redis_client.get(f"vulns:{scan_id}")
    if not vulns_raw:
        raise HTTPException(status_code=404, detail="Vulnerabilities not found")

    vulns = json.loads(vulns_raw)

    enricher = CVSSEnricher()
    enriched = enricher.enrich_vulnerabilities(vulns)
    summary = enricher.get_cvss_summary(enriched)

    return {
        "scan_id": scan_id,
        "summary": summary,
        "vulnerabilities": enriched
    }


# ============== Trends Endpoints ==============

@router_v2.get(
    "/trends/image/{image_name:path}",
    summary="Get Image Vulnerability Trends",
    description="Get vulnerability trends over time for a specific image"
)
async def get_image_trends(
    image_name: str = Path(..., description="Docker image name"),
    days: int = Query(30, ge=1, le=365, description="Number of days"),
    limit: int = Query(100, ge=1, le=500, description="Max data points")
):
    """Get vulnerability trends for an image"""
    analyzer = TrendAnalyzer()
    trends = analyzer.get_image_trends(image_name, days, limit)

    return trends


@router_v2.get(
    "/trends/global",
    summary="Get Global Trends",
    description="Get global vulnerability trends across all scans"
)
async def get_global_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days")
):
    """Get global vulnerability trends"""
    analyzer = TrendAnalyzer()
    trends = analyzer.get_global_trends(days)

    return trends


@router_v2.get(
    "/trends/top-vulnerable",
    summary="Get Top Vulnerable Images",
    description="Get the most vulnerable images"
)
async def get_top_vulnerable(
    days: int = Query(7, ge=1, le=30),
    limit: int = Query(10, ge=1, le=50)
):
    """Get top vulnerable images"""
    analyzer = TrendAnalyzer()
    top_images = analyzer.get_top_vulnerable_images(days, limit)

    return {
        "period_days": days,
        "images": top_images
    }


@router_v2.get(
    "/trends/distribution",
    summary="Get Vulnerability Distribution",
    description="Get vulnerability distribution statistics"
)
async def get_vulnerability_distribution(
    days: int = Query(30, ge=1, le=365)
):
    """Get vulnerability distribution"""
    analyzer = TrendAnalyzer()
    distribution = analyzer.get_vulnerability_distribution(days)

    return distribution


# ============== Export Endpoints ==============

@router_v2.get(
    "/export/{scan_id}/csv",
    summary="Export Vulnerabilities to CSV",
    description="Export vulnerability list as CSV file"
)
async def export_csv(
    scan_id: str = Path(..., description="Scan ID")
):
    """Export vulnerabilities to CSV"""
    redis_client = get_redis_client()

    vulns_raw = redis_client.get(f"vulns:{scan_id}")
    if not vulns_raw:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = json.loads(vulns_raw)

    # Enrich with CVSS
    enricher = CVSSEnricher()
    enriched = enricher.enrich_vulnerabilities(vulns)

    exporter = ReportExporter()
    csv_data = exporter.export_to_csv(scan_id, enriched)

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=vulnerabilities_{scan_id}.csv"
        }
    )


@router_v2.get(
    "/export/{scan_id}/sbom-csv",
    summary="Export SBOM to CSV",
    description="Export SBOM packages as CSV file"
)
async def export_sbom_csv(
    scan_id: str = Path(..., description="Scan ID")
):
    """Export SBOM to CSV"""
    sbom_path = f"{settings.SBOMS_DIR}/{scan_id}_syft_json.json"

    if not os.path.exists(sbom_path):
        raise HTTPException(status_code=404, detail="SBOM not found")

    with open(sbom_path) as f:
        sbom_data = json.load(f)

    packages = sbom_data.get("artifacts", [])

    exporter = ReportExporter()
    csv_data = exporter.export_sbom_to_csv(scan_id, packages)

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=sbom_{scan_id}.csv"
        }
    )


@router_v2.get(
    "/export/{scan_id}/pdf",
    summary="Export Executive Summary PDF",
    description="Generate executive summary PDF report"
)
async def export_executive_pdf(
    scan_id: str = Path(..., description="Scan ID"),
    include_details: bool = Query(False, description="Include vulnerability details")
):
    """Export executive summary PDF"""
    redis_client = get_redis_client()

    # Get scan data
    scan_data = redis_client.hgetall(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get vulnerabilities
    vulns_raw = redis_client.get(f"vulns:{scan_id}")
    vulns = json.loads(vulns_raw) if vulns_raw else []

    # Enrich with CVSS
    enricher = CVSSEnricher()
    enriched = enricher.enrich_vulnerabilities(vulns)

    # Add scan_id to scan_data
    scan_data["scan_id"] = scan_id

    # Convert numeric fields
    for key in ["critical", "high", "medium", "low", "fixable_critical",
                "fixable_high", "fixable_medium", "fixable_low", "total_packages"]:
        scan_data[key] = int(scan_data.get(key, 0) or 0)

    exporter = ReportExporter()
    pdf_data = exporter.generate_executive_summary_pdf(
        scan_data,
        enriched,
        include_details
    )

    return Response(
        content=pdf_data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=executive_summary_{scan_id}.pdf"
        }
    )


@router_v2.get(
    "/export/{scan_id}/detailed-pdf",
    summary="Export Detailed PDF Report",
    description="Generate detailed vulnerability PDF report"
)
async def export_detailed_pdf(
    scan_id: str = Path(..., description="Scan ID")
):
    """Export detailed PDF report"""
    redis_client = get_redis_client()

    scan_data = redis_client.hgetall(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns_raw = redis_client.get(f"vulns:{scan_id}")
    vulns = json.loads(vulns_raw) if vulns_raw else []

    enricher = CVSSEnricher()
    enriched = enricher.enrich_vulnerabilities(vulns)

    scan_data["scan_id"] = scan_id

    exporter = ReportExporter()
    pdf_data = exporter.generate_detailed_pdf(scan_data, enriched)

    return Response(
        content=pdf_data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=detailed_report_{scan_id}.pdf"
        }
    )


# ============== WebSocket Endpoints ==============

@router_v2.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_id: str
):
    """WebSocket endpoint for real-time scan progress"""
    await manager.connect(websocket, scan_id)

    try:
        # Send initial status
        redis_client = get_redis_client()
        current_status = redis_client.get(f"progress:{scan_id}")
        if current_status:
            await websocket.send_text(current_status)

        # Keep connection alive and relay updates
        pubsub = RedisPubSubManager()
        await pubsub.connect()

        async for message in pubsub.listen():
            if message.get("scan_id") == scan_id:
                await websocket.send_json(message)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
    finally:
        await pubsub.disconnect()


@router_v2.websocket("/ws/global")
async def websocket_global(websocket: WebSocket):
    """WebSocket endpoint for all scan updates"""
    await manager.connect(websocket)

    try:
        pubsub = RedisPubSubManager()
        await pubsub.connect()

        async for message in pubsub.listen():
            await websocket.send_json(message)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
    finally:
        await pubsub.disconnect()


# ============== Notification Test Endpoint ==============

@router_v2.post(
    "/test-notification",
    summary="Test Google Chat Notification",
    description="Send a test notification to verify webhook configuration"
)
async def test_notification(
    webhook_url: str = Body(..., embed=True, description="Google Chat webhook URL")
):
    """Test Google Chat notification"""
    notifier = GoogleChatNotifier(webhook_url)

    test_result = {
        "critical": 2,
        "high": 5,
        "medium": 10,
        "low": 15,
        "total_packages": 100,
        "base_image_os": "Ubuntu 22.04",
        "report_url": f"{settings.SERVER_HOST}/reports/test.html",
        "sbom_report_url": f"{settings.SERVER_HOST}/reports/test_sbom.html"
    }

    success = await notifier.send_scan_report(
        test_result,
        "test-image:latest",
        "test-scan-id"
    )

    if success:
        return {"status": "success", "message": "Test notification sent"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send notification")


# ============== Dependency Graph Endpoints ==============

@router_v2.get(
    "/scan/{scan_id}/dependency-graph",
    summary="Get Dependency Graph",
    description="Get package dependency graph with vulnerability mapping"
)
async def get_dependency_graph(
    scan_id: str = Path(..., description="Scan ID")
):
    """Get dependency graph for a scan"""
    from app.dependency_analyzer import DependencyAnalyzer

    analyzer = DependencyAnalyzer()
    graph = analyzer.get_dependency_graph(scan_id)

    if "error" in graph:
        raise HTTPException(status_code=404, detail=graph["error"])

    return graph


@router_v2.get(
    "/scan/{scan_id}/package-impact/{package_name}",
    summary="Get Package Impact",
    description="Analyze the impact of a specific package in the dependency tree"
)
async def get_package_impact(
    scan_id: str = Path(..., description="Scan ID"),
    package_name: str = Path(..., description="Package name to analyze")
):
    """Get impact analysis for a specific package"""
    from app.dependency_analyzer import DependencyAnalyzer

    analyzer = DependencyAnalyzer()
    impact = analyzer.get_package_impact(scan_id, package_name)

    if "error" in impact:
        raise HTTPException(status_code=404, detail=impact["error"])

    return impact


# ============== Remediation Endpoints ==============

@router_v2.get(
    "/scan/{scan_id}/remediation",
    summary="Get Remediation Plan",
    description="Get prioritized remediation suggestions for vulnerabilities"
)
async def get_remediation_plan(
    scan_id: str = Path(..., description="Scan ID")
):
    """Get remediation plan for a scan"""
    from app.remediation import RemediationEngine

    engine = RemediationEngine()
    plan = engine.generate_remediation_plan(scan_id)

    if "error" in plan:
        raise HTTPException(status_code=404, detail=plan["error"])

    return plan


@router_v2.get(
    "/scan/{scan_id}/quick-wins",
    summary="Get Quick Wins",
    description="Get high-impact, low-effort remediation actions"
)
async def get_quick_wins(
    scan_id: str = Path(..., description="Scan ID")
):
    """Get quick win remediation actions"""
    from app.remediation import RemediationEngine

    engine = RemediationEngine()
    plan = engine.generate_remediation_plan(scan_id)

    if "error" in plan:
        raise HTTPException(status_code=404, detail=plan["error"])

    return {
        "scan_id": scan_id,
        "quick_wins": plan.get("quick_wins", []),
        "total_actions": len(plan.get("actions", []))
    }


@router_v2.get(
    "/scan/{scan_id}/remediation-script",
    summary="Get Remediation Script",
    description="Get auto-generated shell scripts for remediation"
)
async def get_remediation_script(
    scan_id: str = Path(..., description="Scan ID"),
    package_type: Optional[str] = Query(None, description="Filter by package type (npm, pip, etc.)")
):
    """Get remediation shell script"""
    from app.remediation import RemediationEngine

    engine = RemediationEngine()
    plan = engine.generate_remediation_plan(scan_id)

    if "error" in plan:
        raise HTTPException(status_code=404, detail=plan["error"])

    scripts = plan.get("remediation_script", {})

    if package_type:
        script = scripts.get(package_type, scripts.get("combined", ""))
    else:
        script = scripts.get("combined", "")

    return Response(
        content=script,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=remediation-{scan_id}.sh"}
    )


# ============== Risk Scoring Endpoints ==============

@router_v2.get(
    "/scan/{scan_id}/risk-score",
    summary="Get Risk Score",
    description="Get comprehensive risk score for an image scan"
)
async def get_risk_score(
    scan_id: str = Path(..., description="Scan ID")
):
    """Get overall risk score for a scan"""
    from app.risk_scoring import RiskScoringEngine

    engine = RiskScoringEngine()
    score = engine.calculate_image_risk_score(scan_id)

    if "error" in score:
        raise HTTPException(status_code=404, detail=score["error"])

    return score


@router_v2.get(
    "/risk-weights",
    summary="Get Risk Weights",
    description="Get current risk scoring weights"
)
async def get_risk_weights():
    """Get current risk scoring weights"""
    from app.risk_scoring import RiskScoringEngine

    engine = RiskScoringEngine()
    return {
        "weights": engine.get_weights(),
        "description": {
            "base_cvss": "Weight for base CVSS score",
            "exploitability": "Weight for exploitability metrics",
            "network_exposure": "Weight for network-accessible vulnerabilities",
            "known_exploit": "Weight for known exploits",
            "active_exploitation": "Weight for actively exploited (CISA KEV)",
            "fix_availability": "Weight for fix availability",
            "age": "Weight for vulnerability age",
            "component_criticality": "Weight for critical components"
        }
    }


@router_v2.put(
    "/risk-weights",
    summary="Update Risk Weights",
    description="Update risk scoring weights (must sum to 1.0)"
)
async def update_risk_weights(
    weights: Dict[str, float] = Body(..., description="New weights")
):
    """Update risk scoring weights"""
    from app.risk_scoring import RiskScoringEngine

    engine = RiskScoringEngine()
    updated = engine.update_weights(weights)

    return {
        "status": "updated",
        "weights": updated
    }


# ============== Update Service Endpoints ==============

@router_v2.get(
    "/system/tool-versions",
    summary="Get Tool Versions",
    description="Check versions of scanning tools and available updates"
)
async def get_tool_versions(admin: TokenData = Depends(get_current_admin)):
    """
    Get current and latest versions of scanning tools (Admin only).
    NOTE: Returns cached status. Trigger 'update-db' to refresh from worker.
    """
    from app.updater import UpdateService

    updater = UpdateService()
    return updater.get_cached_tool_status()


@router_v2.get(
    "/system/db-status",
    summary="Get Database Status",
    description="Get vulnerability database status and update information"
)
async def get_db_status(admin: TokenData = Depends(get_current_admin)):
    """
    Get vulnerability database status (Admin only).
    NOTE: Returns cached status. Trigger 'update-db' to refresh from worker.
    """
    from app.updater import UpdateService

    updater = UpdateService()
    return updater.get_cached_db_status()


@router_v2.post(
    "/system/update-db",
    summary="Update Vulnerability Databases",
    description="Trigger manual update of vulnerability databases"
)
async def trigger_db_update(
    background_tasks: BackgroundTasks,
    admin: TokenData = Depends(get_current_admin)
):
    """Trigger vulnerability database update (Admin only)"""
    from app.tasks import update_vulnerability_databases

    # Run in background via Celery
    task = update_vulnerability_databases.apply_async()

    return {
        "status": "triggered",
        "task_id": task.id,
        "message": "Vulnerability database update started. This also refreshes tool version status."
    }


@router_v2.post(
    "/system/refresh-status",
    summary="Refresh System Status",
    description="Trigger refresh of tool versions and database status"
)
async def refresh_system_status(admin: TokenData = Depends(get_current_admin)):
    """Trigger system status refresh (Admin only, runs on worker)"""
    from app.tasks import check_system_status

    # Run via Celery on worker
    task = check_system_status.apply_async()

    return {
        "status": "triggered",
        "task_id": task.id,
        "message": "System status refresh started. Check back in a few seconds."
    }


@router_v2.get(
    "/system/update-history",
    summary="Get Update History",
    description="Get history of vulnerability database updates"
)
async def get_update_history(
    limit: int = Query(20, ge=1, le=100, description="Number of records to return"),
    admin: TokenData = Depends(get_current_admin)
):
    """Get update history (Admin only)"""
    from app.updater import UpdateService

    updater = UpdateService()
    return {
        "history": updater.get_update_history(limit),
        "last_updates": updater.get_last_updates()
    }


@router_v2.get(
    "/system/notifications",
    summary="Get System Notifications",
    description="Get recent system notifications (updates, alerts)"
)
async def get_notifications(
    limit: int = Query(20, ge=1, le=50, description="Number of notifications"),
    admin: TokenData = Depends(get_current_admin)
):
    """Get system notifications (Admin only)"""
    redis_client = get_redis_client()
    entries = redis_client.lrange("notifications", 0, limit - 1)

    return {
        "notifications": [json.loads(e) for e in entries]
    }


# ============== Worker Monitoring Endpoints ==============

@router_v2.get(
    "/workers/status",
    summary="Get Worker Status",
    description="Get comprehensive status of all Celery workers and queues"
)
async def get_workers_status(admin: TokenData = Depends(get_current_admin)):
    """Get comprehensive worker and queue status (Admin only)"""
    from app.worker_monitor import get_monitor

    monitor = get_monitor()
    return monitor.get_comprehensive_status()


@router_v2.get(
    "/workers/queues",
    summary="Get Queue Statistics",
    description="Get statistics for all task queues"
)
async def get_queue_stats(admin: TokenData = Depends(get_current_admin)):
    """Get queue statistics (Admin only)"""
    from app.worker_monitor import get_monitor
    from dataclasses import asdict

    monitor = get_monitor()
    queues = monitor.get_queue_info()
    queue_lengths = monitor.get_queue_lengths()

    return {
        "queues": [asdict(q) for q in queues],
        "total_queued": sum(queue_lengths.values()),
        "by_queue": queue_lengths
    }


@router_v2.get(
    "/workers/list",
    summary="List Workers",
    description="Get list of all active workers with their details"
)
async def list_workers(admin: TokenData = Depends(get_current_admin)):
    """List all active workers (Admin only)"""
    from app.worker_monitor import get_monitor
    from dataclasses import asdict

    monitor = get_monitor()
    workers = monitor.get_worker_stats()
    pings = monitor.ping_workers()

    return {
        "workers": [
            {
                **asdict(w),
                "responsive": pings.get(w.hostname, False)
            }
            for w in workers
        ],
        "total": len(workers),
        "active": len([w for w in workers if w.status == 'online'])
    }


@router_v2.get(
    "/workers/autoscaler",
    summary="Get Autoscaler Status",
    description="Get auto-scaler status and configuration"
)
async def get_autoscaler_status(admin: TokenData = Depends(get_current_admin)):
    """Get auto-scaler status (Admin only)"""
    from app.worker_monitor import get_monitor

    monitor = get_monitor()
    status = monitor.get_autoscaler_status()
    metrics = monitor.get_autoscaler_metrics()
    history = monitor.get_scaling_history(limit=10)

    return {
        "status": status,
        "config": metrics.get('config', {}),
        "recent_history": history
    }


@router_v2.get(
    "/workers/scaling-history",
    summary="Get Scaling History",
    description="Get history of auto-scaling decisions"
)
async def get_scaling_history(
    limit: int = Query(20, ge=1, le=100, description="Number of records to return"),
    admin: TokenData = Depends(get_current_admin)
):
    """Get scaling history (Admin only)"""
    from app.worker_monitor import get_monitor

    monitor = get_monitor()
    history = monitor.get_scaling_history(limit=limit)

    return {
        "history": history,
        "total": len(history)
    }


@router_v2.get(
    "/workers/tasks",
    summary="Get Task Statistics",
    description="Get task execution statistics"
)
async def get_task_stats(admin: TokenData = Depends(get_current_admin)):
    """Get task statistics (Admin only)"""
    from app.worker_monitor import get_monitor

    monitor = get_monitor()
    return monitor.get_task_stats()


@router_v2.post(
    "/workers/ping",
    summary="Ping Workers",
    description="Ping all workers to check responsiveness"
)
async def ping_workers(admin: TokenData = Depends(get_current_admin)):
    """Ping all workers (Admin only)"""
    from app.worker_monitor import get_monitor

    monitor = get_monitor()
    pings = monitor.ping_workers()

    return {
        "results": pings,
        "total": len(pings),
        "responsive": sum(1 for v in pings.values() if v)
    }


@router_v2.delete(
    "/workers/queues/{queue_name}",
    summary="Purge Queue",
    description="Purge all tasks from a specific queue (use with caution)"
)
async def purge_queue(
    queue_name: str = Path(..., description="Queue name to purge"),
    admin: TokenData = Depends(get_current_admin)
):
    """Purge a queue (Admin only)"""
    from app.worker_monitor import get_monitor

    valid_queues = ['high_priority', 'default', 'batch', 'low_priority', 'system']
    if queue_name not in valid_queues:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid queue name. Valid queues: {valid_queues}"
        )

    monitor = get_monitor()
    try:
        purged = monitor.purge_queue(queue_name)
        logger.warning(f"Queue {queue_name} purged", queue=queue_name, purged_count=purged)
        return {
            "status": "purged",
            "queue": queue_name,
            "purged_count": purged
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router_v2.get(
    "/workers/health",
    summary="Worker Health Check",
    description="Quick health check for worker infrastructure"
)
async def workers_health(admin: TokenData = Depends(get_current_admin)):
    """Quick health check for workers (Admin only)"""
    from app.worker_monitor import get_monitor

    monitor = get_monitor()

    try:
        redis_ok = monitor._check_redis_health()
        workers = monitor.get_worker_stats()
        pings = monitor.ping_workers()

        worker_count = len(workers)
        responsive_count = sum(1 for v in pings.values() if v)

        status = "healthy"
        if not redis_ok:
            status = "unhealthy"
        elif worker_count == 0:
            status = "degraded"
        elif responsive_count < worker_count:
            status = "degraded"

        return {
            "status": status,
            "redis": "connected" if redis_ok else "disconnected",
            "workers": {
                "total": worker_count,
                "responsive": responsive_count
            },
            "queues": monitor.get_queue_lengths()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


# ============== EPSS/KEV Enrichment Endpoints ==============

@router_v2.get(
    "/scan/{scan_id}/enriched",
    summary="Get Enriched Vulnerabilities",
    description="Get vulnerabilities with EPSS scores and KEV status for a scan"
)
async def get_enriched_vulnerabilities(
    scan_id: str = Path(..., description="Scan ID"),
    sort_by: str = Query("risk_priority", description="Sort field: risk_priority, epss_score, severity"),
    kev_only: bool = Query(False, description="Show only KEV vulnerabilities"),
    min_epss: float = Query(0.0, ge=0, le=1, description="Minimum EPSS score filter")
):
    """Get enriched vulnerability data for a scan"""
    redis_client = get_redis_client()

    # Get vulnerabilities
    vulns_raw = redis_client.get(f"vulns:{scan_id}")
    if not vulns_raw:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    vulns = json.loads(vulns_raw)

    # Filter if needed
    filtered = vulns
    if kev_only:
        filtered = [v for v in filtered if v.get("in_kev", False)]
    if min_epss > 0:
        filtered = [v for v in filtered if (v.get("epss_score") or 0) >= min_epss]

    # Sort
    if sort_by == "epss_score":
        filtered.sort(key=lambda x: -(x.get("epss_score") or 0))
    elif sort_by == "severity":
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        filtered.sort(key=lambda x: severity_order.get(x.get("severity", "").lower(), 99))
    else:  # risk_priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        filtered.sort(key=lambda x: (
            priority_order.get(x.get("risk_priority", "info"), 99),
            -(x.get("epss_score") or 0)
        ))

    # Get enrichment summary
    enrichment = redis_client.get(f"enrichment:{scan_id}")
    summary = json.loads(enrichment) if enrichment else {}

    # Get scan metadata
    scan_data = redis_client.hgetall(scan_id)

    return {
        "scan_id": scan_id,
        "image_name": scan_data.get("image_name", ""),
        "total_vulnerabilities": len(vulns),
        "filtered_count": len(filtered),
        "enrichment_summary": {
            "kev_matches": summary.get("kev_matches", int(scan_data.get("kev_matches", 0))),
            "epss_enriched": summary.get("epss_enriched", int(scan_data.get("epss_enriched", 0))),
            "high_risk_vulns": summary.get("high_risk_vulns", int(scan_data.get("high_risk_vulns", 0)))
        },
        "vulnerabilities": filtered
    }


@router_v2.get(
    "/scan/{scan_id}/kev-matches",
    summary="Get KEV Matches",
    description="Get only vulnerabilities that are in CISA KEV catalog"
)
async def get_kev_matches(scan_id: str = Path(..., description="Scan ID")):
    """Get vulnerabilities that are in the KEV catalog"""
    redis_client = get_redis_client()

    vulns_raw = redis_client.get(f"vulns:{scan_id}")
    if not vulns_raw:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    vulns = json.loads(vulns_raw)
    kev_vulns = [v for v in vulns if v.get("in_kev", False)]

    # Get KEV details for each
    kev_client = KEVClient()
    for vuln in kev_vulns:
        cve_id = vuln.get("id", "")
        kev_details = kev_client.get_kev_details(cve_id)
        if kev_details:
            vuln["kev_details"] = kev_details

    return {
        "scan_id": scan_id,
        "total_kev_matches": len(kev_vulns),
        "vulnerabilities": kev_vulns
    }


@router_v2.get(
    "/scan/{scan_id}/high-risk",
    summary="Get High Risk Vulnerabilities",
    description="Get critical priority vulnerabilities (KEV or high EPSS)"
)
async def get_high_risk_vulns(scan_id: str = Path(..., description="Scan ID")):
    """Get high risk vulnerabilities based on KEV status and EPSS scores"""
    redis_client = get_redis_client()

    vulns_raw = redis_client.get(f"vulns:{scan_id}")
    if not vulns_raw:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    vulns = json.loads(vulns_raw)

    # High risk = KEV or EPSS >= 0.4 or critical severity with EPSS >= 0.1
    high_risk = [
        v for v in vulns
        if v.get("risk_priority") in ["critical", "high"]
        or v.get("in_kev", False)
        or (v.get("epss_score") or 0) >= 0.4
    ]

    # Sort by risk
    high_risk.sort(key=lambda x: (
        0 if x.get("in_kev") else 1,
        -(x.get("epss_score") or 0)
    ))

    return {
        "scan_id": scan_id,
        "total_high_risk": len(high_risk),
        "vulnerabilities": high_risk
    }


@router_v2.get(
    "/kev/status",
    summary="Get KEV Database Status",
    description="Get CISA KEV database statistics and last update time"
)
async def get_kev_status():
    """Get KEV database status (public endpoint)"""
    kev_client = KEVClient()
    return kev_client.get_kev_stats()


@router_v2.post(
    "/kev/update",
    summary="Update KEV Database",
    description="Force update of CISA KEV database"
)
async def force_kev_update(admin: TokenData = Depends(get_current_admin)):
    """Force update the KEV database (Admin only)"""
    result = update_kev_database()
    return result


@router_v2.get(
    "/kev/check/{cve_id}",
    summary="Check CVE in KEV",
    description="Check if a specific CVE is in the KEV catalog"
)
async def check_cve_in_kev(cve_id: str = Path(..., description="CVE ID to check")):
    """Check if a CVE is in the KEV catalog"""
    kev_client = KEVClient()

    is_kev = kev_client.is_in_kev(cve_id)
    details = kev_client.get_kev_details(cve_id) if is_kev else None

    return {
        "cve_id": cve_id.upper(),
        "in_kev": is_kev,
        "details": details
    }


@router_v2.post(
    "/epss/lookup",
    summary="Lookup EPSS Scores",
    description="Get EPSS scores for a list of CVEs"
)
async def lookup_epss_scores(cve_ids: List[str] = Body(..., description="List of CVE IDs")):
    """Lookup EPSS scores for multiple CVEs"""
    if not cve_ids:
        raise HTTPException(status_code=400, detail="CVE list cannot be empty")

    if len(cve_ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 CVEs per request")

    epss_client = EPSSClient()
    scores = epss_client.get_epss_scores(cve_ids)

    return {
        "requested": len(cve_ids),
        "found": len(scores),
        "scores": scores
    }


@router_v2.get(
    "/cache/status",
    summary="Get Digest Cache Status",
    description="Get scan result cache statistics"
)
async def get_cache_status(admin: TokenData = Depends(get_current_admin)):
    """Get digest cache statistics (Admin only)"""
    cache = DigestCache()
    return cache.get_cache_stats()


@router_v2.delete(
    "/cache/invalidate/{image_name:path}",
    summary="Invalidate Image Cache",
    description="Invalidate cached scan for a specific image"
)
async def invalidate_image_cache(
    image_name: str = Path(..., description="Image name to invalidate"),
    admin: TokenData = Depends(get_current_admin)
):
    """Invalidate cache for an image (Admin only)"""
    cache = DigestCache()
    digest = cache.get_image_digest(image_name)

    if not digest:
        return {"status": "not_found", "message": "No cached digest found for image"}

    invalidated = cache.invalidate_cache(digest)

    return {
        "status": "invalidated" if invalidated else "not_cached",
        "image_name": image_name,
        "digest": digest[:12] + "..." if digest else None
    }
