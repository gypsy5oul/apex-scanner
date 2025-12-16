"""
API Routes for the Security Scanner
Includes batch scanning, comparison, vulnerability search, and history endpoints
"""
import os
import json
import uuid
import re
import redis
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Path, Body
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field, field_validator
from enum import Enum

from app.tasks import scan_image, batch_scan_images
from app.config import settings
from app.logging_config import get_logger, LogContext
from app.metrics import (
    SCANS_TOTAL, SCANS_IN_PROGRESS, BATCH_SCANS_TOTAL, BATCH_SIZE,
    API_REQUESTS, extract_registry
)

# Configure structured logger
logger = get_logger(__name__)

# Redis connection pool for better performance
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=settings.REDIS_MAX_CONNECTIONS,
    decode_responses=True
)

def get_redis_client() -> redis.Redis:
    """Get Redis client from connection pool"""
    return redis.Redis(connection_pool=redis_pool)


def scan_redis_keys(redis_client: redis.Redis, pattern: str, count: int = 100) -> list:
    """
    Use SCAN instead of KEYS for better performance on large datasets.
    SCAN is O(1) per call vs KEYS which is O(N) and blocks Redis.

    Args:
        redis_client: Redis client instance
        pattern: Key pattern to match (e.g., "history:*")
        count: Hint for number of keys per SCAN iteration

    Returns:
        List of matching keys
    """
    keys = []
    cursor = 0
    while True:
        cursor, batch = redis_client.scan(cursor, match=pattern, count=count)
        keys.extend(batch)
        if cursor == 0:
            break
    return keys


def get_recent_scan_ids(redis_client: redis.Redis, limit: int = 100) -> list:
    """
    Get recent scan IDs from the sorted set (most efficient).
    Falls back to scanning history keys if sorted set is empty.

    Args:
        redis_client: Redis client instance
        limit: Maximum number of scan IDs to return

    Returns:
        List of recent scan IDs ordered by timestamp (newest first)
    """
    # Try to get from sorted set first (O(log N) operation)
    recent = redis_client.zrevrange("recent_scans", 0, limit - 1)
    if recent:
        return recent

    # Fallback: scan history keys (only if sorted set not populated yet)
    # This is slower but ensures backward compatibility
    history_keys = scan_redis_keys(redis_client, "history:*", count=200)
    scan_ids = []
    for key in history_keys[:limit * 2]:  # Get more than needed to sort later
        ids = redis_client.lrange(key, 0, 2)
        scan_ids.extend(ids)
    return scan_ids[:limit]


# Enums
class ScanStatus(str, Enum):
    """Enumeration of possible scan statuses"""
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilitySeverity(str, Enum):
    """Enumeration of vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    UNKNOWN = "unknown"


class SBOMFormat(str, Enum):
    """SBOM format types"""
    SPDX_JSON = "spdx-json"
    CYCLONEDX_JSON = "cyclonedx-json"
    SYFT_JSON = "syft-json"


# Request Models
class ScanRequest(BaseModel):
    """Request model for initiating a security scan"""
    image_name: str = Field(
        ...,
        description="The full name of the Docker image to scan",
        min_length=1,
        max_length=500,
        examples=["nginx:latest"]
    )

    @field_validator('image_name')
    @classmethod
    def validate_image_name(cls, v: str) -> str:
        """Validate and sanitize image name"""
        # Remove any shell metacharacters for security
        dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f"Invalid character in image name: {char}")
        return v.strip()

    model_config = {
        "json_schema_extra": {
            "example": {"image_name": "ubuntu:20.04"}
        }
    }


class BatchScanRequest(BaseModel):
    """Request model for batch scanning multiple images"""
    images: List[str] = Field(
        ...,
        description="List of Docker images to scan",
        min_length=1,
        max_length=50,
        examples=[["nginx:latest", "alpine:3.18", "python:3.11"]]
    )

    @field_validator('images')
    @classmethod
    def validate_images(cls, v: List[str]) -> List[str]:
        """Validate all image names in batch"""
        if len(v) > settings.BATCH_MAX_IMAGES:
            raise ValueError(f"Maximum {settings.BATCH_MAX_IMAGES} images per batch")

        dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '\n', '\r']
        validated = []
        for img in v:
            for char in dangerous_chars:
                if char in img:
                    raise ValueError(f"Invalid character in image name: {char}")
            validated.append(img.strip())
        return validated


# Response Models
class ScanResponse(BaseModel):
    """Response model for scan initiation"""
    scan_id: str = Field(..., description="Unique identifier for the scan")
    status: ScanStatus = Field(..., description="Current status of the scan")
    message: str = Field(..., description="Human-readable status message")


class BatchScanResponse(BaseModel):
    """Response model for batch scan initiation"""
    batch_id: str = Field(..., description="Unique identifier for the batch")
    scan_ids: List[str] = Field(..., description="Individual scan IDs")
    total_images: int = Field(..., description="Number of images in batch")
    status: str = Field(..., description="Batch status")


class VulnerabilityCount(BaseModel):
    """Model for vulnerability counts by severity"""
    critical: int = Field(0, description="Number of critical vulnerabilities")
    high: int = Field(0, description="Number of high-severity vulnerabilities")
    medium: int = Field(0, description="Number of medium-severity vulnerabilities")
    low: int = Field(0, description="Number of low-severity vulnerabilities")
    negligible: int = Field(0, description="Number of negligible vulnerabilities")
    unknown: int = Field(0, description="Number of unknown-severity vulnerabilities")


class MultiScannerData(BaseModel):
    """Multi-scanner specific data"""
    scanners_used: List[str] = Field(default_factory=list, description="List of scanners used")
    grype_unique: int = Field(0, description="Vulnerabilities found only by Grype")
    trivy_unique: int = Field(0, description="Vulnerabilities found only by Trivy")
    both_scanners: int = Field(0, description="Vulnerabilities found by both scanners")
    total_secrets: int = Field(0, description="Secrets detected by Trivy")


class SBOMInfo(BaseModel):
    """SBOM information"""
    total_packages: int = Field(0, description="Total packages in SBOM")
    available_formats: List[str] = Field(default_factory=list, description="Available SBOM formats")
    spdx_url: Optional[str] = None
    cyclonedx_url: Optional[str] = None
    syft_url: Optional[str] = None
    html_report_url: Optional[str] = Field(None, description="HTML visualization of SBOM")


class BaseImageInfo(BaseModel):
    """Base image/OS information"""
    os_name: Optional[str] = Field(None, description="Operating system name")
    os_version: Optional[str] = Field(None, description="Operating system version")
    os_full_name: Optional[str] = Field(None, description="Full OS description")
    os_id: Optional[str] = Field(None, description="OS identifier")
    os_cpe: Optional[str] = Field(None, description="Common Platform Enumeration string")


class ImageMetadata(BaseModel):
    """Docker image metadata"""
    image_id: Optional[str] = Field(None, description="Docker image ID")
    image_size: int = Field(0, description="Image size in bytes")
    image_layers: int = Field(0, description="Number of image layers")


class EnhancedScanResult(BaseModel):
    """Enhanced scan result model with multi-scanner data"""
    scan_id: str = Field(..., description="Unique identifier for the scan")
    status: ScanStatus = Field(..., description="Current status of the scan")
    image_name: str = Field(..., description="Scanned Docker image name")
    vulnerabilities: VulnerabilityCount = Field(..., description="Total vulnerability counts")
    fixable_vulnerabilities: Optional[VulnerabilityCount] = Field(None, description="Fixable vulnerability counts")
    multi_scanner: Optional[MultiScannerData] = Field(None, description="Multi-scanner specific data")
    sbom: Optional[SBOMInfo] = Field(None, description="SBOM information")
    base_image: Optional[BaseImageInfo] = Field(None, description="Base image/OS information")
    image_metadata: Optional[ImageMetadata] = Field(None, description="Docker image metadata")
    report_url: Optional[str] = Field(None, description="URL to the detailed HTML report")
    error: Optional[str] = Field(None, description="Error message if scan failed")
    scan_timestamp: Optional[str] = Field(None, description="Scan completion timestamp")
    status_code: int = Field(..., description="HTTP status code indicating security status")


class VulnerabilityItem(BaseModel):
    """Individual vulnerability item"""
    cve_id: str = Field(..., description="CVE identifier")
    severity: str = Field(..., description="Vulnerability severity")
    package_name: str = Field(..., description="Affected package name")
    package_version: str = Field(..., description="Affected package version")
    fix_available: bool = Field(..., description="Whether a fix is available")
    fix_version: Optional[str] = Field(None, description="Version with fix")
    description: Optional[str] = Field(None, description="Vulnerability description")
    cvss_score: Optional[str] = Field(None, description="CVSS score")
    found_by: List[str] = Field(default_factory=list, description="Scanners that found this")
    scan_id: str = Field(..., description="Scan ID where found")
    image_name: str = Field(..., description="Image name")


class ScanHistoryItem(BaseModel):
    """Scan history entry"""
    scan_id: str
    image_name: str
    scan_timestamp: str
    status: str
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int


class ComparisonResult(BaseModel):
    """Result of comparing two scans"""
    scan_id_1: str
    scan_id_2: str
    image_1: str
    image_2: str
    new_vulnerabilities: List[Dict[str, Any]]
    fixed_vulnerabilities: List[Dict[str, Any]]
    unchanged_vulnerabilities: int
    summary: Dict[str, Any]


# Create router
router = APIRouter(prefix="/api/v1", tags=["security"])


# Helper functions
def parse_scan_result(scan_id: str, result: Dict[str, str]) -> EnhancedScanResult:
    """Parse Redis hash result into EnhancedScanResult"""
    # Convert numeric fields
    for key in ["critical", "high", "medium", "low", "negligible", "unknown",
                "fixable_critical", "fixable_high", "fixable_medium", "fixable_low",
                "total_secrets", "total_packages", "grype_unique_count",
                "trivy_unique_count", "both_scanners_count", "image_size", "image_layers"]:
        result[key] = int(result.get(key, 0) or 0)

    vulnerabilities = VulnerabilityCount(
        critical=result["critical"],
        high=result["high"],
        medium=result["medium"],
        low=result["low"],
        negligible=result["negligible"],
        unknown=result["unknown"]
    )

    fixable_vulnerabilities = VulnerabilityCount(
        critical=result.get("fixable_critical", 0),
        high=result.get("fixable_high", 0),
        medium=result.get("fixable_medium", 0),
        low=result.get("fixable_low", 0),
        negligible=0,
        unknown=0
    )

    scanners_used = result.get("scanners_used", "").split(",") if result.get("scanners_used") else []

    multi_scanner = MultiScannerData(
        scanners_used=scanners_used,
        grype_unique=result.get("grype_unique_count", 0),
        trivy_unique=result.get("trivy_unique_count", 0),
        both_scanners=result.get("both_scanners_count", 0),
        total_secrets=result.get("total_secrets", 0)
    )

    # Parse SBOM URLs
    try:
        sbom_urls = json.loads(result.get("sbom_urls", "{}") or "{}")
    except json.JSONDecodeError:
        sbom_urls = {}

    sbom_info = SBOMInfo(
        total_packages=result.get("total_packages", 0),
        available_formats=list(sbom_urls.keys()),
        spdx_url=sbom_urls.get("spdx-json"),
        cyclonedx_url=sbom_urls.get("cyclonedx-json"),
        syft_url=sbom_urls.get("syft-json"),
        html_report_url=result.get("sbom_report_url")
    )

    base_image_info = None
    if result.get("base_image_os") and result.get("base_image_os") != "Unknown":
        base_image_info = BaseImageInfo(
            os_name=result.get("base_image_os_name"),
            os_version=result.get("base_image_os_version"),
            os_full_name=result.get("base_image_os"),
            os_id=result.get("base_image_os_id"),
            os_cpe=result.get("base_image_cpe")
        )

    image_metadata = None
    if result.get("image_id"):
        image_metadata = ImageMetadata(
            image_id=result.get("image_id"),
            image_size=result.get("image_size", 0),
            image_layers=result.get("image_layers", 0)
        )

    status_code = 200 if (result["critical"] == 0 and result["high"] == 0) else 403

    return EnhancedScanResult(
        scan_id=scan_id,
        status=result.get("status", ScanStatus.IN_PROGRESS),
        image_name=result.get("image_name", ""),
        vulnerabilities=vulnerabilities,
        fixable_vulnerabilities=fixable_vulnerabilities,
        multi_scanner=multi_scanner,
        sbom=sbom_info,
        base_image=base_image_info,
        image_metadata=image_metadata,
        report_url=result.get("report_url"),
        error=result.get("error"),
        scan_timestamp=result.get("scan_timestamp"),
        status_code=status_code
    )


# Endpoints
@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=202,
    responses={
        202: {"description": "Scan initiated successfully"},
        400: {"description": "Invalid request parameters"},
        500: {"description": "Internal server error"}
    },
    summary="Start Multi-Scanner Docker Image Security Scan",
    description="""
    Initiates a comprehensive security scan using multiple scanners (Grype + Trivy)
    and generates SBOM using Syft.
    """
)
async def start_scan(request: ScanRequest = Body(...)):
    """Start a new multi-scanner security analysis"""
    redis_client = get_redis_client()

    with LogContext(image=request.image_name, operation="start_scan"):
        try:
            scan_id = str(uuid.uuid4())

            logger.info(
                "Initiating scan",
                scan_id=scan_id,
                image=request.image_name
            )

            # Initialize scan state in Redis with TTL
            redis_client.hset(scan_id, mapping={
                "status": ScanStatus.IN_PROGRESS,
                "image_name": request.image_name,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
                "total_secrets": 0,
                "total_packages": 0,
                "report_url": "",
                "sbom_urls": "{}",
                "created_at": datetime.utcnow().isoformat()
            })
            redis_client.expire(scan_id, settings.SCAN_RESULT_TTL)

            # Track in image history index
            history_key = f"history:{request.image_name}"
            redis_client.lpush(history_key, scan_id)
            redis_client.ltrim(history_key, 0, settings.MAX_HISTORY_PER_IMAGE - 1)
            redis_client.expire(history_key, settings.SCAN_RESULT_TTL)

            # Update metrics
            SCANS_TOTAL.labels(
                image_registry=extract_registry(request.image_name),
                scan_type="single"
            ).inc()
            SCANS_IN_PROGRESS.inc()

            # Submit scan task to Celery
            scan_image.apply_async(args=[request.image_name, scan_id])

            logger.info(
                "Scan task submitted",
                scan_id=scan_id,
                image=request.image_name
            )

            return ScanResponse(
                scan_id=scan_id,
                status=ScanStatus.IN_PROGRESS,
                message="Multi-scanner analysis initiated successfully"
            )

        except Exception as e:
            logger.error(
                "Error initiating scan",
                error=str(e),
                image=request.image_name
            )
            raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/scan/batch",
    response_model=BatchScanResponse,
    status_code=202,
    summary="Start Batch Scan for Multiple Images",
    description="Initiate scanning for multiple Docker images in a single request"
)
async def start_batch_scan(request: BatchScanRequest = Body(...)):
    """Start batch scanning for multiple images"""
    redis_client = get_redis_client()

    with LogContext(operation="batch_scan", image_count=len(request.images)):
        try:
            batch_id = str(uuid.uuid4())
            scan_ids = []

            logger.info(
                "Initiating batch scan",
                batch_id=batch_id,
                image_count=len(request.images)
            )

            for image_name in request.images:
                scan_id = str(uuid.uuid4())
                scan_ids.append(scan_id)

                # Initialize each scan
                redis_client.hset(scan_id, mapping={
                    "status": ScanStatus.IN_PROGRESS,
                    "image_name": image_name,
                    "batch_id": batch_id,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "negligible": 0,
                    "unknown": 0,
                    "total_secrets": 0,
                    "total_packages": 0,
                    "report_url": "",
                    "sbom_urls": "{}",
                    "created_at": datetime.utcnow().isoformat()
                })
                redis_client.expire(scan_id, settings.SCAN_RESULT_TTL)

                # Track in image history
                history_key = f"history:{image_name}"
                redis_client.lpush(history_key, scan_id)
                redis_client.ltrim(history_key, 0, settings.MAX_HISTORY_PER_IMAGE - 1)

                # Update metrics
                SCANS_TOTAL.labels(
                    image_registry=extract_registry(image_name),
                    scan_type="batch"
                ).inc()

            # Store batch metadata
            redis_client.hset(f"batch:{batch_id}", mapping={
                "scan_ids": json.dumps(scan_ids),
                "images": json.dumps(request.images),
                "total_images": len(request.images),
                "status": "in_progress",
                "created_at": datetime.utcnow().isoformat()
            })
            redis_client.expire(f"batch:{batch_id}", settings.SCAN_RESULT_TTL)

            # Update batch metrics
            BATCH_SCANS_TOTAL.inc()
            BATCH_SIZE.observe(len(request.images))
            SCANS_IN_PROGRESS.inc(len(request.images))

            # Submit batch task
            batch_scan_images.apply_async(
                args=[request.images, scan_ids, batch_id]
            )

            logger.info(
                "Batch scan tasks submitted",
                batch_id=batch_id,
                scan_ids=scan_ids
            )

            return BatchScanResponse(
                batch_id=batch_id,
                scan_ids=scan_ids,
                total_images=len(request.images),
                status="in_progress"
            )

        except Exception as e:
            logger.error(
                "Error initiating batch scan",
                error=str(e),
                batch_size=len(request.images)
            )
            raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/scan/batch/{batch_id}",
    summary="Get Batch Scan Status",
    description="Retrieve status and results for all scans in a batch"
)
async def get_batch_status(batch_id: str = Path(..., description="Batch ID")):
    """Get status of a batch scan"""
    redis_client = get_redis_client()

    batch_data = redis_client.hgetall(f"batch:{batch_id}")
    if not batch_data:
        raise HTTPException(status_code=404, detail="Batch not found")

    scan_ids = json.loads(batch_data.get("scan_ids", "[]"))
    images = json.loads(batch_data.get("images", "[]"))

    results = []
    completed = 0
    failed = 0

    for scan_id in scan_ids:
        result = redis_client.hgetall(scan_id)
        if result:
            status = result.get("status", "unknown")
            if status == "completed":
                completed += 1
            elif status == "failed":
                failed += 1
            results.append({
                "scan_id": scan_id,
                "image_name": result.get("image_name"),
                "status": status,
                "critical": int(result.get("critical", 0)),
                "high": int(result.get("high", 0)),
                "report_url": result.get("report_url")
            })

    batch_status = "completed" if completed == len(scan_ids) else \
                   "failed" if failed == len(scan_ids) else "in_progress"

    return {
        "batch_id": batch_id,
        "status": batch_status,
        "total_images": len(scan_ids),
        "completed": completed,
        "failed": failed,
        "in_progress": len(scan_ids) - completed - failed,
        "scans": results
    }


@router.get(
    "/scan/{scan_id}",
    response_model=EnhancedScanResult,
    responses={
        200: {"description": "Scan results retrieved successfully"},
        404: {"description": "Scan not found"},
        500: {"description": "Internal server error"}
    },
    summary="Get Multi-Scanner Scan Results"
)
async def get_scan_result(
    scan_id: str = Path(..., description="Unique identifier of the scan")
):
    """Fetch enhanced scan results with multi-scanner data"""
    redis_client = get_redis_client()

    with LogContext(scan_id=scan_id, operation="get_result"):
        try:
            result = redis_client.hgetall(scan_id)
            if not result:
                logger.warning("Scan not found", scan_id=scan_id)
                raise HTTPException(status_code=404, detail="Scan not found")

            return parse_scan_result(scan_id, result)

        except HTTPException:
            raise
        except Exception as e:
            logger.error("Error retrieving scan results", error=str(e), scan_id=scan_id)
            raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/compare/{scan_id_1}/{scan_id_2}",
    response_model=ComparisonResult,
    summary="Compare Two Scans",
    description="Compare vulnerabilities between two scans to see what's new, fixed, or unchanged"
)
async def compare_scans(
    scan_id_1: str = Path(..., description="First scan ID"),
    scan_id_2: str = Path(..., description="Second scan ID (usually newer)")
):
    """Compare vulnerabilities between two scans"""
    redis_client = get_redis_client()

    with LogContext(operation="compare_scans", scan_id_1=scan_id_1, scan_id_2=scan_id_2):
        # Fetch both scans
        result1 = redis_client.hgetall(scan_id_1)
        result2 = redis_client.hgetall(scan_id_2)

        if not result1:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id_1} not found")
        if not result2:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id_2} not found")

        # Get vulnerability details from stored data
        vulns1_raw = redis_client.get(f"vulns:{scan_id_1}")
        vulns2_raw = redis_client.get(f"vulns:{scan_id_2}")

        vulns1 = json.loads(vulns1_raw) if vulns1_raw else []
        vulns2 = json.loads(vulns2_raw) if vulns2_raw else []

        # Create sets for comparison (using CVE:package as key)
        set1 = {f"{v.get('id', '')}:{v.get('package_name', '')}" for v in vulns1}
        set2 = {f"{v.get('id', '')}:{v.get('package_name', '')}" for v in vulns2}

        # Find differences
        new_keys = set2 - set1
        fixed_keys = set1 - set2
        unchanged_keys = set1 & set2

        # Build detailed lists
        new_vulns = [v for v in vulns2 if f"{v.get('id', '')}:{v.get('package_name', '')}" in new_keys]
        fixed_vulns = [v for v in vulns1 if f"{v.get('id', '')}:{v.get('package_name', '')}" in fixed_keys]

        # Calculate summary
        def count_by_severity(vulns):
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for v in vulns:
                sev = v.get("severity", "").lower()
                if sev in counts:
                    counts[sev] += 1
            return counts

        logger.info(
            "Scans compared",
            scan_id_1=scan_id_1,
            scan_id_2=scan_id_2,
            new_count=len(new_vulns),
            fixed_count=len(fixed_vulns)
        )

        return ComparisonResult(
            scan_id_1=scan_id_1,
            scan_id_2=scan_id_2,
            image_1=result1.get("image_name", ""),
            image_2=result2.get("image_name", ""),
            new_vulnerabilities=new_vulns,
            fixed_vulnerabilities=fixed_vulns,
            unchanged_vulnerabilities=len(unchanged_keys),
            summary={
                "new_by_severity": count_by_severity(new_vulns),
                "fixed_by_severity": count_by_severity(fixed_vulns),
                "scan_1_total": len(vulns1),
                "scan_2_total": len(vulns2),
                "scan_1_timestamp": result1.get("scan_timestamp"),
                "scan_2_timestamp": result2.get("scan_timestamp")
            }
        )


@router.get(
    "/vulnerabilities/search",
    summary="Search Vulnerabilities",
    description="Search for vulnerabilities by CVE ID, package name, or severity across all scans"
)
async def search_vulnerabilities(
    cve: Optional[str] = Query(None, description="CVE ID to search for"),
    package: Optional[str] = Query(None, description="Package name to search for"),
    severity: Optional[VulnerabilitySeverity] = Query(None, description="Severity level"),
    image: Optional[str] = Query(None, description="Image name filter"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Result offset")
):
    """Search for vulnerabilities across all scans"""
    redis_client = get_redis_client()

    if not any([cve, package, severity, image]):
        raise HTTPException(
            status_code=400,
            detail="At least one search parameter required (cve, package, severity, or image)"
        )

    with LogContext(operation="vulnerability_search", cve=cve, package=package):
        results = []

        # Get all vulnerability indices
        if cve:
            # Search by CVE index
            scan_ids = redis_client.smembers(f"cve_index:{cve.upper()}")
        elif image:
            # Search by image history
            scan_ids = redis_client.lrange(f"history:{image}", 0, -1)
        else:
            # Full scan required - use SCAN instead of KEYS for performance
            vuln_keys = scan_redis_keys(redis_client, "vulns:*", count=200)
            scan_ids = [s.replace("vulns:", "") for s in vuln_keys]

        scan_id_list = list(scan_ids)[:500]  # Limit to prevent overload

        if not scan_id_list:
            return {"total": 0, "offset": offset, "limit": limit, "results": []}

        # Pipeline: Get all vulns and scan data in batch
        pipe = redis_client.pipeline()
        for scan_id in scan_id_list:
            pipe.get(f"vulns:{scan_id}")
            pipe.hgetall(scan_id)
        pipe_results = pipe.execute()

        # Process results in pairs (vulns, scan_data)
        for i, scan_id in enumerate(scan_id_list):
            vulns_raw = pipe_results[i * 2]
            scan_data = pipe_results[i * 2 + 1]

            if not vulns_raw:
                continue

            vulns = json.loads(vulns_raw)
            image_name = scan_data.get("image_name", "") if scan_data else ""

            for vuln in vulns:
                # Apply filters
                if cve and vuln.get("id", "").upper() != cve.upper():
                    continue
                if package and package.lower() not in vuln.get("package_name", "").lower():
                    continue
                if severity and vuln.get("severity", "").lower() != severity.value:
                    continue
                if image and image.lower() not in image_name.lower():
                    continue

                results.append({
                    "cve_id": vuln.get("id"),
                    "severity": vuln.get("severity"),
                    "package_name": vuln.get("package_name"),
                    "package_version": vuln.get("package_version"),
                    "fix_available": vuln.get("fix_available", False),
                    "fix_version": vuln.get("fix_versions", [None])[0] if vuln.get("fix_versions") else None,
                    "description": vuln.get("description", "")[:200],
                    "cvss_score": vuln.get("cvss_score"),
                    "found_by": vuln.get("found_by", []),
                    "scan_id": scan_id,
                    "image_name": image_name
                })

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: severity_order.get(x.get("severity", "").lower(), 99))

        # Apply pagination
        paginated = results[offset:offset + limit]

        logger.info(
            "Vulnerability search completed",
            total_found=len(results),
            returned=len(paginated)
        )

        return {
            "total": len(results),
            "offset": offset,
            "limit": limit,
            "results": paginated
        }


@router.get(
    "/history/{image_name:path}",
    summary="Get Scan History for Image",
    description="Retrieve scan history and trends for a specific Docker image"
)
async def get_image_history(
    image_name: str = Path(..., description="Docker image name"),
    limit: int = Query(20, ge=1, le=100, description="Maximum history entries")
):
    """Get scan history for a specific image"""
    redis_client = get_redis_client()

    with LogContext(operation="get_history", image=image_name):
        history_key = f"history:{image_name}"
        scan_ids = redis_client.lrange(history_key, 0, limit - 1)

        if not scan_ids:
            raise HTTPException(status_code=404, detail=f"No scan history found for {image_name}")

        # Pipeline: Get all scan data in batch
        pipe = redis_client.pipeline()
        for scan_id in scan_ids:
            pipe.hgetall(scan_id)
        scan_results = pipe.execute()

        history = []
        for scan_id, result in zip(scan_ids, scan_results):
            if result:
                history.append({
                    "scan_id": scan_id,
                    "image_name": result.get("image_name"),
                    "scan_timestamp": result.get("scan_timestamp"),
                    "status": result.get("status"),
                    "total_vulnerabilities": sum([
                        int(result.get("critical", 0)),
                        int(result.get("high", 0)),
                        int(result.get("medium", 0)),
                        int(result.get("low", 0))
                    ]),
                    "critical": int(result.get("critical", 0)),
                    "high": int(result.get("high", 0)),
                    "medium": int(result.get("medium", 0)),
                    "low": int(result.get("low", 0)),
                    "total_packages": int(result.get("total_packages", 0)),
                    "report_url": result.get("report_url")
                })

        # Calculate trends if we have multiple scans
        trends = None
        if len(history) >= 2:
            latest = history[0]
            previous = history[1]
            trends = {
                "critical_change": latest["critical"] - previous["critical"],
                "high_change": latest["high"] - previous["high"],
                "total_change": latest["total_vulnerabilities"] - previous["total_vulnerabilities"],
                "improving": latest["total_vulnerabilities"] < previous["total_vulnerabilities"]
            }

        logger.info(
            "History retrieved",
            image=image_name,
            entries=len(history)
        )

        return {
            "image_name": image_name,
            "total_scans": len(history),
            "history": history,
            "trends": trends
        }


@router.get(
    "/reports/{scan_id}",
    responses={
        200: {"description": "Report URL retrieved successfully"},
        404: {"description": "Report not found"}
    },
    summary="Get HTML Report URL"
)
async def get_report(scan_id: str = Path(..., description="Scan ID")):
    """Get the URL for a scan's HTML report"""
    report_path = f"{settings.REPORTS_DIR}/{scan_id}.html"
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found")

    return JSONResponse({
        "report_url": f"{settings.SERVER_HOST}/reports/{scan_id}.html",
        "scan_id": scan_id
    })


@router.get(
    "/sbom/{scan_id}",
    responses={
        200: {"description": "SBOM information retrieved"},
        404: {"description": "SBOM not found"}
    },
    summary="Get SBOM Information"
)
async def get_sbom_info(scan_id: str = Path(..., description="Scan ID")):
    """Get SBOM information and available formats"""
    sbom_files = {}
    for fmt in ["spdx-json", "cyclonedx-json", "syft-json"]:
        file_name = f"{scan_id}_{fmt.replace('-', '_')}.json"
        file_path = f"{settings.SBOMS_DIR}/{file_name}"
        if os.path.exists(file_path):
            sbom_files[fmt] = {
                "format": fmt,
                "download_url": f"{settings.SERVER_HOST}/sboms/{file_name}",
                "api_url": f"/api/v1/sbom/{scan_id}/download/{fmt}"
            }

    if not sbom_files:
        raise HTTPException(status_code=404, detail="No SBOM files found for this scan")

    return JSONResponse({
        "scan_id": scan_id,
        "available_formats": list(sbom_files.keys()),
        "sboms": sbom_files
    })


@router.get(
    "/sbom/{scan_id}/download/{format}",
    responses={
        200: {"description": "SBOM file"},
        404: {"description": "SBOM file not found"}
    },
    summary="Download SBOM File"
)
async def download_sbom(
    scan_id: str = Path(..., description="Scan ID"),
    format: SBOMFormat = Path(..., description="SBOM format")
):
    """Download SBOM file in specified format"""
    file_name = f"{scan_id}_{format.value.replace('-', '_')}.json"
    file_path = f"{settings.SBOMS_DIR}/{file_name}"

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"SBOM file not found: {format.value}")

    return FileResponse(
        path=file_path,
        media_type="application/json",
        filename=file_name
    )


@router.get(
    "/scans/recent",
    summary="Get Recent Scans",
    description="Get a list of recent scans across all images"
)
async def get_recent_scans(
    limit: int = Query(5, ge=1, le=50, description="Number of recent scans to return")
):
    """Get recent scans for dashboard display"""
    redis_client = get_redis_client()

    with LogContext(operation="get_recent_scans"):
        # Get all history keys (using SCAN for performance)
        history_keys = scan_redis_keys(redis_client, "history:*", count=200)

        if not history_keys:
            return {"scans": [], "total": 0}

        # Pipeline 1: Get recent scan IDs from all history lists in batch
        pipe = redis_client.pipeline()
        for key in history_keys:
            pipe.lrange(key, 0, 2)  # Get last 3 from each image
        history_results = pipe.execute()

        # Collect all scan IDs
        all_scan_ids = []
        for scan_ids in history_results:
            all_scan_ids.extend(scan_ids)

        if not all_scan_ids:
            return {"scans": [], "total": 0}

        # Pipeline 2: Get all scan details in batch
        pipe = redis_client.pipeline()
        for scan_id in all_scan_ids:
            pipe.hgetall(scan_id)
        scan_results = pipe.execute()

        # Build response
        all_scans = []
        for scan_id, result in zip(all_scan_ids, scan_results):
            if result:
                timestamp = result.get("scan_timestamp") or result.get("created_at", "")
                all_scans.append({
                    "scan_id": scan_id,
                    "image_name": result.get("image_name", ""),
                    "status": result.get("status", "unknown"),
                    "timestamp": timestamp,
                    "summary": {
                        "critical": int(result.get("critical", 0)),
                        "high": int(result.get("high", 0)),
                        "medium": int(result.get("medium", 0)),
                        "low": int(result.get("low", 0)),
                    },
                    "report_url": result.get("report_url")
                })

        # Sort by timestamp descending
        all_scans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return {
            "scans": all_scans[:limit],
            "total": len(all_scans)
        }


@router.get(
    "/stats",
    summary="Get Scanner Statistics",
    description="Get overall statistics about scans, vulnerabilities, and system health"
)
async def get_stats():
    """Get scanner statistics"""
    redis_client = get_redis_client()

    # Get basic stats from Redis (using SCAN for performance)
    total_scans = len(scan_redis_keys(redis_client, "history:*", count=200))

    return {
        "total_images_scanned": total_scans,
        "scanners_enabled": {
            "grype": settings.ENABLE_GRYPE,
            "trivy": settings.ENABLE_TRIVY,
            "syft": settings.ENABLE_SYFT
        },
        "configuration": {
            "scan_timeout": settings.SCAN_TIMEOUT,
            "result_ttl_days": settings.SCAN_RESULT_TTL // 86400,
            "max_batch_size": settings.BATCH_MAX_IMAGES
        }
    }


@router.get(
    "/api-info",
    response_model=Dict,
    summary="API Information"
)
async def get_api_info():
    """Get comprehensive API documentation"""
    return {
        "api_version": "2.1",
        "base_path": "/api/v1",
        "features": [
            "Multi-scanner vulnerability detection (Grype + Trivy)",
            "Secret detection (Trivy)",
            "SBOM generation (Syft)",
            "Cross-scanner validation",
            "Batch scanning",
            "Scan comparison",
            "Vulnerability search",
            "Scan history & trends",
            "Prometheus metrics",
            "Structured JSON logging"
        ],
        "scanners": {
            "grype": {"enabled": settings.ENABLE_GRYPE, "purpose": "Vulnerability scanning"},
            "trivy": {"enabled": settings.ENABLE_TRIVY, "purpose": "Vulnerabilities + Secrets"},
            "syft": {"enabled": settings.ENABLE_SYFT, "purpose": "SBOM generation"}
        },
        "endpoints": [
            {"method": "POST", "path": "/scan", "description": "Start single image scan"},
            {"method": "POST", "path": "/scan/batch", "description": "Start batch scan"},
            {"method": "GET", "path": "/scan/{scan_id}", "description": "Get scan results"},
            {"method": "GET", "path": "/scan/batch/{batch_id}", "description": "Get batch status"},
            {"method": "GET", "path": "/compare/{id1}/{id2}", "description": "Compare two scans"},
            {"method": "GET", "path": "/vulnerabilities/search", "description": "Search vulnerabilities"},
            {"method": "GET", "path": "/history/{image}", "description": "Get image scan history"},
            {"method": "GET", "path": "/reports/{scan_id}", "description": "Get HTML report URL"},
            {"method": "GET", "path": "/sbom/{scan_id}", "description": "Get SBOM info"},
            {"method": "GET", "path": "/stats", "description": "Get scanner statistics"}
        ],
        "documentation_url": "/docs",
        "openapi_spec": "/openapi.json",
        "metrics_url": "/metrics"
    }
