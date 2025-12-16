"""
Celery tasks for security scanning
Includes batch scanning, metrics, and structured logging
"""
import os
import json
import redis
import traceback
from celery import Celery, group
from datetime import datetime
from typing import List, Dict, Any

from app.config import settings
from app.scanners.orchestrator import ScannerOrchestrator
from app.logging_config import get_logger, configure_logging, LogContext
from app.metrics import (
    SCANS_IN_PROGRESS, SCANS_COMPLETED, SCAN_DURATION,
    VULNERABILITIES_FOUND, SECRETS_FOUND, PACKAGES_FOUND,
    record_vulnerabilities, record_secrets, record_packages,
    track_scan_duration
)
from app.enrichment import (
    VulnerabilityEnricher,
    DigestCache,
    KEVClient,
    enrich_scan_results,
    check_digest_cache,
    cache_scan_by_digest,
    update_kev_database as update_kev_db
)
from jinja2 import Environment, FileSystemLoader

# Configure structured logging
configure_logging(
    json_logs=(settings.LOG_FORMAT == "json"),
    log_level=settings.LOG_LEVEL
)
logger = get_logger(__name__)

# Initialize Redis client with connection pool
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=settings.REDIS_MAX_CONNECTIONS,
    decode_responses=True
)


def get_redis_client() -> redis.Redis:
    """Get Redis client from connection pool"""
    return redis.Redis(connection_pool=redis_pool)


# Initialize Celery with enhanced configuration
celery = Celery(
    "scanner",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

# Define task queues with priorities
from kombu import Queue, Exchange

# Define exchanges
default_exchange = Exchange('default', type='direct')
priority_exchange = Exchange('priority', type='direct')

celery.conf.update(
    # Serialization
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,

    # Task tracking
    task_track_started=True,
    task_time_limit=settings.SCAN_TIMEOUT * 3,
    task_soft_time_limit=settings.SCAN_TIMEOUT * 2,

    # Worker settings
    worker_max_tasks_per_child=50,
    worker_prefetch_multiplier=1,
    worker_concurrency=4,

    # Reliability
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_acks_on_failure_or_timeout=False,

    # Queue configuration
    task_queues=(
        Queue('high_priority', exchange=priority_exchange, routing_key='high', queue_arguments={'x-max-priority': 10}),
        Queue('default', exchange=default_exchange, routing_key='default', queue_arguments={'x-max-priority': 5}),
        Queue('batch', exchange=default_exchange, routing_key='batch', queue_arguments={'x-max-priority': 3}),
        Queue('low_priority', exchange=default_exchange, routing_key='low', queue_arguments={'x-max-priority': 1}),
        Queue('system', exchange=default_exchange, routing_key='system'),
    ),

    task_default_queue='default',
    task_default_exchange='default',
    task_default_routing_key='default',

    # Task routing
    task_routes={
        'scan_image': {'queue': 'high_priority', 'routing_key': 'high'},
        'scan_image_priority': {'queue': 'high_priority', 'routing_key': 'high'},
        'batch_scan_images': {'queue': 'batch', 'routing_key': 'batch'},
        'scan_base_images': {'queue': 'low_priority', 'routing_key': 'low'},
        'update_vulnerability_databases': {'queue': 'system', 'routing_key': 'system'},
        'check_system_status': {'queue': 'system', 'routing_key': 'system'},
        'update_kev_database': {'queue': 'system', 'routing_key': 'system'},
    },

    # Result backend settings
    result_expires=86400,  # Results expire after 24 hours
    result_extended=True,

    # Broker settings for better performance
    broker_pool_limit=50,
    broker_connection_retry_on_startup=True,
    broker_transport_options={
        'visibility_timeout': 43200,  # 12 hours
        'fanout_prefix': True,
        'fanout_patterns': True,
    },
)

# Setup Jinja2 environment
env = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True
)

# Ensure directories exist
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
os.makedirs(settings.SBOMS_DIR, exist_ok=True)


def generate_sbom_html_report(
    scan_id: str,
    image_name: str,
    sbom_data: dict,
    base_image_info: dict = None,
    image_metadata: dict = None
) -> str:
    """
    Generate beautiful HTML report for SBOM data

    Args:
        scan_id: Unique scan identifier
        image_name: Scanned Docker image name
        sbom_data: SBOM data from Syft
        base_image_info: Base image/OS information
        image_metadata: Image metadata (size, layers, etc.)

    Returns:
        Path to generated HTML report
    """
    try:
        logger.info(
            "Generating SBOM HTML report",
            scan_id=scan_id,
            image=image_name
        )

        template = env.get_template("sbom_report_template.html")
        report_file = os.path.join(settings.REPORTS_DIR, f"{scan_id}_sbom.html")

        # Extract packages from SBOM
        artifacts = sbom_data.get("artifacts", [])
        packages = []
        package_types = {}

        for artifact in artifacts:
            licenses = []
            for lic in artifact.get("licenses", []):
                if isinstance(lic, str):
                    licenses.append(lic)
                elif isinstance(lic, dict):
                    licenses.append(lic.get("value", "Unknown"))

            pkg_type = artifact.get("type", "Unknown")
            package_types[pkg_type] = package_types.get(pkg_type, 0) + 1

            packages.append({
                "name": artifact.get("name", "Unknown"),
                "version": artifact.get("version", "Unknown"),
                "type": pkg_type,
                "language": artifact.get("language", ""),
                "licenses": licenses
            })

        # Record package metrics
        record_packages(package_types)

        # Sort packages by name
        packages.sort(key=lambda x: x["name"].lower())

        # Get statistics
        distro = sbom_data.get("distro", {})
        source = sbom_data.get("source", {})
        metadata = source.get("metadata", {})

        # Count languages
        languages = {}
        for pkg in packages:
            if pkg["language"]:
                languages[pkg["language"]] = languages.get(pkg["language"], 0) + 1

        # Count licenses
        all_licenses = set()
        for pkg in packages:
            all_licenses.update(pkg["licenses"])

        # Sort for display
        package_types_sorted = sorted(package_types.items(), key=lambda x: x[1], reverse=True)
        languages_sorted = sorted(languages.items(), key=lambda x: x[1], reverse=True)

        # Format image size
        image_size = image_metadata.get("image_size", 0) if image_metadata else metadata.get("imageSize", 0)
        image_size_mb = image_size / (1024 * 1024)
        if image_size_mb > 1024:
            image_size_human = f"{image_size_mb / 1024:.2f} GB"
        else:
            image_size_human = f"{image_size_mb:.2f} MB"

        # Prepare base image info
        base_image = None
        if base_image_info:
            base_image = base_image_info
        elif distro:
            base_image = {
                "os_pretty_name": distro.get("prettyName", "Unknown"),
                "os_version": distro.get("version", "Unknown"),
                "os_id": distro.get("id", "Unknown"),
                "os_cpe": distro.get("cpeName", "Unknown")
            }

        # Generate report context
        report_context = {
            "image_name": image_name,
            "scan_id": scan_id,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_packages": len(packages),
            "total_languages": len(languages),
            "total_licenses": len(all_licenses),
            "image_layers": image_metadata.get("layer_count", 0) if image_metadata else len(metadata.get("layers", [])),
            "image_size_human": image_size_human,
            "packages": packages,
            "package_types": package_types,
            "package_types_sorted": package_types_sorted,
            "languages": languages,
            "languages_sorted": languages_sorted,
            "max_package_count": max(package_types.values()) if package_types else 1,
            "max_language_count": max(languages.values()) if languages else 1,
            "base_image": base_image,
            "vuln_report_url": f"{settings.SERVER_HOST}/reports/{scan_id}.html"
        }

        # Render and save report
        html_content = template.render(**report_context)
        with open(report_file, "w") as f:
            f.write(html_content)

        logger.info(
            "SBOM HTML report generated",
            scan_id=scan_id,
            report_path=report_file
        )
        return report_file

    except Exception as e:
        logger.error(
            "Error generating SBOM HTML report",
            scan_id=scan_id,
            error=str(e)
        )
        traceback.print_exc()
        return None


def generate_enhanced_html_report(
    scan_id: str,
    image_name: str,
    merged_results: dict
) -> tuple:
    """
    Generate enhanced HTML report with multi-scanner results

    Args:
        scan_id: Unique scan identifier
        image_name: Scanned Docker image name
        merged_results: Merged results from all scanners

    Returns:
        Tuple of (report_file_path, vulnerability_counts)
    """
    try:
        logger.info(
            "Generating enhanced HTML report",
            scan_id=scan_id,
            image=image_name
        )

        template = env.get_template("enhanced_report_template.html")
        report_file = os.path.join(settings.REPORTS_DIR, f"{scan_id}.html")

        # Prepare vulnerabilities for display
        all_vulns = merged_results.get("vulnerabilities", {}).get("all", [])

        # Filter for fixable vulnerabilities with relevant severities
        fixable_vulns = [
            v for v in all_vulns
            if v.get("fix_available", False) and
            v.get("severity", "Unknown").upper() in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        ]

        # Sort by severity and confidence
        severity_order = {"CRITICAL": 0, "Critical": 0, "HIGH": 1, "High": 1,
                         "MEDIUM": 2, "Medium": 2, "LOW": 3, "Low": 3}
        confidence_order = {"high": 0, "medium": 1, "low": 2}

        fixable_vulns.sort(
            key=lambda x: (
                severity_order.get(x.get("severity", "Unknown"), 999),
                confidence_order.get(x.get("confidence", "low"), 999)
            )
        )

        # Calculate statistics
        severity_counts = merged_results.get("severity_counts", {})
        fixable_counts = merged_results.get("fixable_counts", {})

        # Record vulnerability metrics
        for scanner in merged_results.get("scanners_used", []):
            record_vulnerabilities(severity_counts, scanner)

        # Record secret metrics
        secrets = merged_results.get("secrets", [])
        record_secrets(secrets)

        # Get SBOM statistics
        sbom_stats = merged_results.get("sbom", {}).get("statistics", {})

        # Generate report context
        report_context = {
            "image_name": image_name,
            "scan_id": scan_id,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "vulnerabilities": fixable_vulns,
            "all_vulnerabilities": all_vulns,
            "severity_counts": severity_counts,
            "fixable_counts": fixable_counts,
            "total_vulnerabilities": len(all_vulns),
            "total_fixable": len(fixable_vulns),
            "secrets": secrets,
            "total_secrets": merged_results.get("total_secrets", 0),
            "scanners_used": merged_results.get("scanners_used", []),
            "grype_unique": merged_results.get("grype_unique_count", 0),
            "trivy_unique": merged_results.get("trivy_unique_count", 0),
            "both_scanners": merged_results.get("both_scanners_count", 0),
            "sbom_statistics": sbom_stats,
            "scan_summary": {
                "status": "Failed" if (severity_counts.get("Critical", 0) + severity_counts.get("High", 0)) > 0 else "Passed",
                "total_packages": sbom_stats.get("total_packages", 0),
                "scanners": ", ".join(merged_results.get("scanners_used", [])),
                "multi_scanner_validation": len(merged_results.get("scanners_used", [])) > 1
            }
        }

        # Render and save report
        html_content = template.render(**report_context)
        with open(report_file, "w") as f:
            f.write(html_content)

        logger.info(
            "Enhanced report generated",
            scan_id=scan_id,
            report_path=report_file,
            total_vulns=len(all_vulns)
        )

        return report_file, {
            "total": severity_counts,
            "fixable": fixable_counts
        }

    except Exception as e:
        logger.error(
            "Error generating HTML report",
            scan_id=scan_id,
            error=str(e)
        )
        traceback.print_exc()
        return None, None


@celery.task(bind=True, name='scan_image', max_retries=3, default_retry_delay=30)
def scan_image(self, image_name: str, scan_id: str, skip_cache: bool = False) -> Dict[str, Any]:
    """
    Execute multi-scanner vulnerability and SBOM analysis

    Args:
        image_name: Docker image to scan
        scan_id: Unique scan identifier
        skip_cache: If True, bypass digest cache and force rescan

    Returns:
        Dictionary with complete scan results
    """
    redis_client = get_redis_client()
    start_time = datetime.now()
    image_digest = None

    with LogContext(scan_id=scan_id, image=image_name, task="scan_image"):
        logger.info(
            "Starting multi-scanner analysis",
            scan_id=scan_id,
            image=image_name
        )

        try:
            # Check digest cache first (unless skipping)
            if not skip_cache:
                image_digest, cached_scan = check_digest_cache(image_name)
                if cached_scan:
                    logger.info(
                        "Cache hit - returning cached scan result",
                        scan_id=scan_id,
                        image=image_name,
                        cached_scan_id=cached_scan.get("scan_id"),
                        digest=image_digest[:12] if image_digest else "unknown"
                    )
                    # Copy cached result to new scan_id
                    cached_scan_id = cached_scan.get("scan_id")
                    if cached_scan_id and cached_scan_id != scan_id:
                        # Copy the scan data from cached scan
                        cached_data = redis_client.hgetall(cached_scan_id)
                        if cached_data:
                            cached_data["scan_id"] = scan_id
                            cached_data["cached_from"] = cached_scan_id
                            cached_data["cache_hit"] = "true"
                            cached_data["scan_timestamp"] = datetime.now().isoformat()
                            redis_client.hset(scan_id, mapping=cached_data)
                            redis_client.expire(scan_id, settings.SCAN_RESULT_TTL)

                            # Copy vulnerabilities
                            vulns = redis_client.get(f"vulns:{cached_scan_id}")
                            if vulns:
                                redis_client.set(f"vulns:{scan_id}", vulns, ex=settings.SCAN_RESULT_TTL)

                            SCANS_COMPLETED.labels(status='cache_hit', scanner='all').inc()
                            return {**cached_data, "scan_id": scan_id, "cache_hit": True}
            else:
                # Get digest for later caching even when skipping cache
                digest_cache = DigestCache()
                image_digest = digest_cache.get_image_digest(image_name)

            # Initialize scanner orchestrator
            orchestrator = ScannerOrchestrator()

            # Run all scans in parallel
            merged_results = orchestrator.run_all_scans(
                image_name=image_name,
                scan_id=scan_id,
                base_output_dir="/tmp",
                sbom_output_dir=settings.SBOMS_DIR,
                timeout=settings.SCAN_TIMEOUT
            )

            # Check if any scanner succeeded
            if not merged_results.get("scanners_used"):
                error_msg = "All scanners failed"
                logger.error(
                    error_msg,
                    scan_id=scan_id,
                    summary=merged_results.get('summary', {})
                )
                redis_client.hset(scan_id, mapping={"status": "failed", "error": error_msg})
                SCANS_COMPLETED.labels(status='failure', scanner='all').inc()
                SCANS_IN_PROGRESS.dec()
                return {"scan_id": scan_id, "status": "failed", "error": error_msg}

            # Generate enhanced HTML report
            html_report, vuln_counts = generate_enhanced_html_report(scan_id, image_name, merged_results)

            if not html_report:
                error_msg = "Failed to generate HTML report"
                logger.error(error_msg, scan_id=scan_id)
                redis_client.hset(scan_id, mapping={"status": "failed", "error": error_msg})
                SCANS_COMPLETED.labels(status='failure', scanner='report').inc()
                SCANS_IN_PROGRESS.dec()
                return {"scan_id": scan_id, "status": "failed", "error": error_msg}

            # Prepare SBOM URLs
            sbom_urls = {}
            sbom_formats = merged_results.get("sbom", {}).get("formats", {})
            for fmt, data in sbom_formats.items():
                if isinstance(data, dict) and data.get("success"):
                    sbom_urls[fmt] = f"{settings.SERVER_HOST}/sboms/{scan_id}_{fmt.replace('-', '_')}.json"

            # Extract base image information from SBOM statistics
            sbom_stats = merged_results.get("sbom", {}).get("statistics", {})
            base_image_info = sbom_stats.get("base_image", {})
            image_metadata = sbom_stats.get("image_metadata", {})

            # Generate SBOM HTML report
            sbom_html_report = None
            try:
                syft_json_path = f"{settings.SBOMS_DIR}/{scan_id}_syft_json.json"
                if os.path.exists(syft_json_path):
                    with open(syft_json_path, "r") as f:
                        sbom_data = json.load(f)
                    sbom_html_report = generate_sbom_html_report(
                        scan_id,
                        image_name,
                        sbom_data,
                        base_image_info,
                        image_metadata
                    )
            except Exception as e:
                logger.warning(
                    "Failed to generate SBOM HTML report",
                    scan_id=scan_id,
                    error=str(e)
                )

            # Store vulnerability details for comparison/search
            all_vulns = merged_results.get("vulnerabilities", {}).get("all", [])

            # Enrich vulnerabilities with EPSS scores and KEV status
            enriched_vulns, enrichment_summary = enrich_scan_results(all_vulns, scan_id)

            # Store enriched vulnerabilities
            redis_client.set(
                f"vulns:{scan_id}",
                json.dumps(enriched_vulns),
                ex=settings.SCAN_RESULT_TTL
            )

            # Index vulnerabilities by CVE for search
            for vuln in enriched_vulns:
                cve_id = vuln.get("id", "").upper()
                if cve_id:
                    redis_client.sadd(f"cve_index:{cve_id}", scan_id)
                    redis_client.expire(f"cve_index:{cve_id}", settings.SCAN_RESULT_TTL)

            # Calculate scan duration
            duration = (datetime.now() - start_time).total_seconds()

            # Update Redis with comprehensive results
            redis_result = {
                "status": "completed",
                "image_name": image_name,

                # Total vulnerability counts
                "critical": vuln_counts["total"].get("Critical", 0),
                "high": vuln_counts["total"].get("High", 0),
                "medium": vuln_counts["total"].get("Medium", 0),
                "low": vuln_counts["total"].get("Low", 0),
                "negligible": vuln_counts["total"].get("Negligible", 0),
                "unknown": vuln_counts["total"].get("Unknown", 0),

                # Fixable vulnerability counts
                "fixable_critical": vuln_counts["fixable"].get("Critical", 0),
                "fixable_high": vuln_counts["fixable"].get("High", 0),
                "fixable_medium": vuln_counts["fixable"].get("Medium", 0),
                "fixable_low": vuln_counts["fixable"].get("Low", 0),

                # Multi-scanner specific data
                "total_unique_vulnerabilities": merged_results.get("total_unique_vulnerabilities", 0),
                "grype_unique_count": merged_results.get("grype_unique_count", 0),
                "trivy_unique_count": merged_results.get("trivy_unique_count", 0),
                "both_scanners_count": merged_results.get("both_scanners_count", 0),

                # Secrets
                "total_secrets": merged_results.get("total_secrets", 0),

                # SBOM data
                "total_packages": sbom_stats.get("total_packages", 0),

                # Base image information
                "base_image_os": base_image_info.get("os_pretty_name", "Unknown"),
                "base_image_os_name": base_image_info.get("os_name", "Unknown"),
                "base_image_os_version": base_image_info.get("os_version", "Unknown"),
                "base_image_os_id": base_image_info.get("os_id", "Unknown"),
                "base_image_cpe": base_image_info.get("os_cpe", "Unknown"),

                # Image metadata
                "image_id": image_metadata.get("image_id", "Unknown"),
                "image_size": image_metadata.get("image_size", 0),
                "image_layers": image_metadata.get("layer_count", 0),

                # URLs
                "report_url": f"{settings.SERVER_HOST}/reports/{scan_id}.html",
                "sbom_report_url": f"{settings.SERVER_HOST}/reports/{scan_id}_sbom.html" if sbom_html_report else "",
                "sbom_urls": json.dumps(sbom_urls),

                # Scanner metadata
                "scanners_used": ",".join(merged_results.get("scanners_used", [])),
                "scan_timestamp": datetime.now().isoformat(),
                "scan_duration_seconds": duration,

                # EPSS/KEV enrichment data
                "kev_matches": enrichment_summary.get("kev_matches", 0),
                "epss_enriched": enrichment_summary.get("epss_enriched", 0),
                "high_risk_vulns": enrichment_summary.get("high_risk_vulns", 0),
                "image_digest": image_digest or ""
            }

            redis_client.hset(scan_id, mapping=redis_result)

            # Cache by digest for future identical image scans
            if image_digest:
                cache_scan_by_digest(
                    digest=image_digest,
                    scan_id=scan_id,
                    image_name=image_name,
                    summary={
                        "critical": redis_result["critical"],
                        "high": redis_result["high"],
                        "medium": redis_result["medium"],
                        "low": redis_result["low"],
                        "kev_matches": redis_result["kev_matches"],
                        "high_risk_vulns": redis_result["high_risk_vulns"]
                    }
                )

            # Update metrics
            SCANS_COMPLETED.labels(status='success', scanner='all').inc()
            SCANS_IN_PROGRESS.dec()
            SCAN_DURATION.labels(scanner='combined').observe(duration)

            logger.info(
                "Multi-scanner analysis completed",
                scan_id=scan_id,
                image=image_name,
                scanners=merged_results.get("scanners_used", []),
                total_cves=merged_results.get("total_unique_vulnerabilities", 0),
                secrets=merged_results.get("total_secrets", 0),
                packages=sbom_stats.get("total_packages", 0),
                kev_matches=enrichment_summary.get("kev_matches", 0),
                high_risk_vulns=enrichment_summary.get("high_risk_vulns", 0),
                duration_seconds=duration
            )

            return {**redis_result, "scan_id": scan_id}

        except Exception as e:
            error_msg = f"Unexpected error scanning {image_name}: {str(e)}"
            logger.error(
                "Scan failed with exception",
                scan_id=scan_id,
                image=image_name,
                error=str(e),
                traceback=traceback.format_exc()
            )

            redis_client.hset(scan_id, mapping={"status": "failed", "error": error_msg})
            SCANS_COMPLETED.labels(status='failure', scanner='exception').inc()
            SCANS_IN_PROGRESS.dec()

            # Retry on transient errors
            if self.request.retries < self.max_retries:
                raise self.retry(exc=e, countdown=30 * (self.request.retries + 1))

            return {"scan_id": scan_id, "status": "failed", "error": error_msg}


@celery.task(bind=True, name='batch_scan_images', max_retries=2, default_retry_delay=60)
def batch_scan_images(
    self,
    images: List[str],
    scan_ids: List[str],
    batch_id: str
) -> Dict[str, Any]:
    """
    Execute batch scanning for multiple images IN PARALLEL using Celery group()

    Args:
        images: List of Docker images to scan
        scan_ids: List of scan IDs corresponding to each image
        batch_id: Unique batch identifier

    Returns:
        Dictionary with batch results
    """
    redis_client = get_redis_client()

    with LogContext(batch_id=batch_id, task="batch_scan"):
        logger.info(
            "Starting parallel batch scan",
            batch_id=batch_id,
            image_count=len(images)
        )

        # Update batch status to processing
        redis_client.hset(f"batch:{batch_id}", mapping={
            "status": "processing",
            "started_at": datetime.now().isoformat()
        })

        # Create a group of parallel scan tasks
        # This runs all scans concurrently instead of sequentially
        scan_tasks = group(
            scan_image.s(image_name, scan_id)
            for image_name, scan_id in zip(images, scan_ids)
        )

        # Execute all tasks in parallel and wait for results
        # timeout is per-task timeout * 1.5 to allow for some overhead
        try:
            group_result = scan_tasks.apply_async()

            # Wait for all tasks to complete with a reasonable timeout
            # Each scan can take up to SCAN_TIMEOUT, but they run in parallel
            # So total time should be closer to single scan time, not N * scan time
            timeout = settings.SCAN_TIMEOUT * 2  # Allow 2x single scan timeout for entire batch

            task_results = group_result.get(
                timeout=timeout,
                propagate=False  # Don't raise exceptions, collect all results
            )
        except Exception as e:
            logger.error(
                "Batch scan group execution failed",
                batch_id=batch_id,
                error=str(e)
            )
            # Mark batch as failed
            redis_client.hset(f"batch:{batch_id}", mapping={
                "status": "failed",
                "error": str(e),
                "completed_at": datetime.now().isoformat()
            })
            raise

        # Process results from parallel execution
        results = []
        for i, (image_name, scan_id) in enumerate(zip(images, scan_ids)):
            try:
                task_result = task_results[i] if i < len(task_results) else None

                if task_result is None:
                    status = "failed"
                    error = "No result returned"
                elif isinstance(task_result, Exception):
                    status = "failed"
                    error = str(task_result)
                elif isinstance(task_result, dict):
                    status = "completed" if task_result.get("status") == "completed" else "failed"
                    error = task_result.get("error")
                else:
                    status = "failed"
                    error = f"Unexpected result type: {type(task_result)}"

                result_entry = {
                    "scan_id": scan_id,
                    "image_name": image_name,
                    "status": status
                }
                if error:
                    result_entry["error"] = error

                results.append(result_entry)

            except Exception as e:
                logger.error(
                    "Error processing batch scan result",
                    batch_id=batch_id,
                    scan_id=scan_id,
                    image=image_name,
                    error=str(e)
                )
                results.append({
                    "scan_id": scan_id,
                    "image_name": image_name,
                    "status": "failed",
                    "error": str(e)
                })

        # Update batch status
        completed = sum(1 for r in results if r["status"] == "completed")
        failed = len(results) - completed

        batch_status = "completed" if completed == len(results) else \
                       "partial" if completed > 0 else "failed"

        redis_client.hset(f"batch:{batch_id}", mapping={
            "status": batch_status,
            "completed_count": completed,
            "failed_count": failed,
            "completed_at": datetime.now().isoformat()
        })

        logger.info(
            "Parallel batch scan completed",
            batch_id=batch_id,
            completed=completed,
            failed=failed,
            status=batch_status
        )

        return {
            "batch_id": batch_id,
            "status": batch_status,
            "completed": completed,
            "failed": failed,
            "results": results
        }


@celery.task(
    bind=True,
    name='scan_base_images',
    soft_time_limit=7200,  # 2 hours soft limit
    time_limit=7500        # 2 hours 5 min hard limit
)
def scan_base_images(self, batch_size: int = 5) -> Dict[str, Any]:
    """
    Scan all registered base images in parallel batches
    This task is called by Celery Beat on schedule

    Args:
        batch_size: Number of images to scan concurrently (default: 5)
    """
    import uuid
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from app.base_image_tracker import BaseImageTracker

    redis_client = get_redis_client()
    tracker = BaseImageTracker()

    def scan_single_base_image(base_image: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a single base image - runs in thread pool"""
        image_name = base_image.get("full_name")
        scan_id = str(uuid.uuid4())

        # Get a fresh Redis connection for this thread
        thread_redis = get_redis_client()

        try:
            logger.info(
                "Scanning base image",
                image=image_name,
                scan_id=scan_id
            )

            # Initialize scan in Redis
            thread_redis.hset(scan_id, mapping={
                "status": "in_progress",
                "image_name": image_name,
                "created_at": datetime.now().isoformat(),
                "scan_type": "base_image"
            })
            thread_redis.expire(scan_id, settings.SCAN_RESULT_TTL)

            # Track in image history index (for Recent Scans display)
            history_key = f"history:{image_name}"
            thread_redis.lpush(history_key, scan_id)
            thread_redis.ltrim(history_key, 0, settings.MAX_HISTORY_PER_IMAGE - 1)
            thread_redis.expire(history_key, settings.SCAN_RESULT_TTL)

            # Run the scan
            result = scan_image(image_name, scan_id)

            # Update base image tracker with results
            if result.get("status") == "completed":
                tracker.update_base_image_vulns(
                    base_image.get("image_name"),
                    base_image.get("image_tag"),
                    scan_id,
                    {
                        "critical": result.get("critical", 0),
                        "high": result.get("high", 0),
                        "medium": result.get("medium", 0),
                        "low": result.get("low", 0),
                        "fixable_critical": result.get("fixable_critical", 0),
                        "fixable_high": result.get("fixable_high", 0),
                        "fixable_medium": result.get("fixable_medium", 0),
                        "fixable_low": result.get("fixable_low", 0),
                    }
                )

            return {
                "image": image_name,
                "scan_id": scan_id,
                "status": result.get("status", "unknown"),
                "critical": result.get("critical", 0),
                "high": result.get("high", 0),
                "medium": result.get("medium", 0),
                "low": result.get("low", 0)
            }

        except Exception as e:
            logger.error(
                "Failed to scan base image",
                image=image_name,
                error=str(e)
            )
            # Mark as failed in Redis
            thread_redis.hset(scan_id, "status", "failed")
            thread_redis.hset(scan_id, "error", str(e))
            return {
                "image": image_name,
                "scan_id": scan_id,
                "status": "failed",
                "error": str(e)
            }

    with LogContext(task="scan_base_images"):
        logger.info("Starting scheduled base image scan (parallel mode)")

        base_images = tracker.list_base_images()

        if not base_images:
            logger.info("No base images registered, skipping scan")
            return {"status": "skipped", "reason": "no_base_images"}

        total_images = len(base_images)
        logger.info(f"Scanning {total_images} base images in batches of {batch_size}")

        results = []

        # Process images in parallel batches
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            # Submit all tasks
            future_to_image = {
                executor.submit(scan_single_base_image, img): img
                for img in base_images if img.get("full_name")
            }

            # Collect results as they complete
            for future in as_completed(future_to_image):
                base_image = future_to_image[future]
                try:
                    result = future.result(timeout=600)  # 10 min timeout per image
                    results.append(result)
                    logger.info(
                        f"Completed {len(results)}/{total_images}",
                        image=base_image.get("full_name"),
                        status=result.get("status")
                    )
                except Exception as e:
                    logger.error(
                        "Base image scan future failed",
                        image=base_image.get("full_name"),
                        error=str(e)
                    )
                    results.append({
                        "image": base_image.get("full_name"),
                        "scan_id": "unknown",
                        "status": "failed",
                        "error": str(e)
                    })

        completed = sum(1 for r in results if r["status"] == "completed")
        failed = sum(1 for r in results if r["status"] == "failed")

        logger.info(
            "Base image scan batch completed",
            total=len(results),
            completed=completed,
            failed=failed
        )

        return {
            "status": "completed",
            "total": len(results),
            "completed": completed,
            "failed": failed,
            "results": results
        }


# Configure Celery Beat schedule for base image scanning
celery.conf.beat_schedule = {
    'scan-base-images-daily': {
        'task': 'scan_base_images',
        'schedule': 86400.0,  # Every 24 hours (in seconds)
        'options': {'queue': 'low_priority'}  # Must match task_routes config
    },
    'update-vulnerability-db-daily': {
        'task': 'update_vulnerability_databases',
        'schedule': 43200.0,  # Every 12 hours (in seconds)
        'options': {'queue': 'system'}  # Must match task_routes config
    },
    'update-kev-database': {
        'task': 'update_kev_database',
        'schedule': 21600.0,  # Every 6 hours (in seconds)
        'options': {'queue': 'system'}  # Must match task_routes config
    },
}
celery.conf.timezone = 'UTC'


# ============== Vulnerability Database Update Task ==============

@celery.task(bind=True, name='update_vulnerability_databases')
def update_vulnerability_databases(self) -> Dict[str, Any]:
    """
    Celery task to update vulnerability databases (Grype, Trivy)
    Runs every 12 hours via beat schedule
    Also checks and caches tool versions for the System Status page
    """
    from app.updater import UpdateService

    logger.info("Starting scheduled vulnerability database update")

    try:
        updater = UpdateService()

        # First check and cache tool versions (runs on worker where tools are installed)
        logger.info("Checking tool versions...")
        tool_status = updater.check_tool_updates()

        # Then run DB updates
        result = updater.run_scheduled_updates()

        # Add tool status to result
        result["tool_versions"] = tool_status

        logger.info(
            "Vulnerability database update completed",
            all_successful=result.get("all_successful", False),
            updates=len(result.get("updates", []))
        )

        return result

    except Exception as e:
        logger.error(f"Vulnerability database update failed: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


@celery.task(bind=True, name='check_system_status')
def check_system_status(self) -> Dict[str, Any]:
    """
    Celery task to check and cache system status (tool versions, DB info)
    Can be triggered manually or on startup
    """
    from app.updater import UpdateService

    logger.info("Checking system status...")

    try:
        updater = UpdateService()

        # Check tool versions
        tool_status = updater.check_tool_updates()

        # Get DB info
        db_info = updater._get_grype_db_info()

        # Cache DB status
        import json
        from app.updater import DB_STATUS_KEY, TOOL_STATUS_TTL
        db_status = {
            "grype": db_info,
            "last_updates": updater.get_last_updates(),
            "grype_hours_since_update": 0,
            "grype_update_due": False
        }
        updater.redis.setex(DB_STATUS_KEY, TOOL_STATUS_TTL, json.dumps(db_status))

        logger.info("System status check completed")

        return {
            "tool_versions": tool_status,
            "db_status": db_status,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"System status check failed: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


# ============== KEV Database Update Task ==============

@celery.task(bind=True, name='update_kev_database')
def update_kev_database(self) -> Dict[str, Any]:
    """
    Celery task to update CISA KEV (Known Exploited Vulnerabilities) database.
    Runs every 6 hours via beat schedule.
    """
    logger.info("Starting CISA KEV database update")

    try:
        result = update_kev_db()

        if result.get("status") == "updated":
            logger.info(
                "KEV database updated successfully",
                total_cves=result.get("total_cves", 0),
                catalog_version=result.get("catalog_version")
            )
        else:
            logger.warning(
                "KEV database update issue",
                status=result.get("status"),
                error=result.get("error")
            )

        return result

    except Exception as e:
        logger.error(f"KEV database update failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
