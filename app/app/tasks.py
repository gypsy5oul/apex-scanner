"""
Celery tasks for security scanning
Includes batch scanning, metrics, and structured logging
"""
import os
import json
import socket
import traceback
from celery import Celery
from celery.signals import worker_ready
from datetime import datetime, timezone
from typing import List, Dict, Any

from app.config import settings, get_redis_client
from app.time_utils import now_iso
from app.scanners.orchestrator import ScannerOrchestrator
from app.scanner_errors import classify_scanner_errors, summarize_scan_failure
from app.license_compliance import evaluate as evaluate_licenses, to_dict as licenses_to_dict
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

# Initialize Celery with authenticated Redis URL
celery = Celery(
    "scanner",
    broker=settings.effective_redis_url,
    backend=settings.effective_redis_url
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
        'cleanup_old_scan_artifacts': {'queue': 'system', 'routing_key': 'system'},
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

# Configure Redis TLS for Celery broker/backend if enabled
if settings.REDIS_TLS_ENABLED:
    _ssl_conf = {
        "ssl_cert_reqs": "required",
    }
    if settings.REDIS_TLS_CA_PATH:
        _ssl_conf["ssl_ca_certs"] = settings.REDIS_TLS_CA_PATH
    if settings.REDIS_TLS_CERT_PATH:
        _ssl_conf["ssl_certfile"] = settings.REDIS_TLS_CERT_PATH
    if settings.REDIS_TLS_KEY_PATH:
        _ssl_conf["ssl_keyfile"] = settings.REDIS_TLS_KEY_PATH
    celery.conf.update(
        broker_use_ssl=_ssl_conf,
        redis_backend_use_ssl=_ssl_conf,
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


# ---------------------------------------------------------------------------
# Worker startup: validate scanner binaries and publish health to Redis
# ---------------------------------------------------------------------------

def validate_scanner_binaries() -> Dict[str, Any]:
    """Run preflight checks on all enabled scanners and return status dict."""
    from app.scanners.grype_scanner import GrypeScanner
    from app.scanners.trivy_scanner import TrivyScanner
    from app.scanners.syft_scanner import SyftScanner

    results: Dict[str, Any] = {}
    for name, cls, enabled in [
        ("grype", GrypeScanner, settings.ENABLE_GRYPE),
        ("trivy", TrivyScanner, settings.ENABLE_TRIVY),
        ("syft", SyftScanner, settings.ENABLE_SYFT),
    ]:
        if not enabled:
            results[name] = {"status": "disabled"}
            continue
        try:
            scanner = cls()
            ok, err = scanner.preflight()
            results[name] = {
                "status": "healthy" if ok else "unhealthy",
                "error": err,
                "version": scanner.get_scanner_version() if ok else None,
            }
        except Exception as exc:
            results[name] = {"status": "unhealthy", "error": str(exc)}
    return results


@worker_ready.connect
def on_worker_ready(**kwargs):
    """Validate scanner binaries when the Celery worker starts."""
    hostname = socket.gethostname()
    logger.info(f"Worker {hostname} starting — running scanner preflight checks")

    health = validate_scanner_binaries()
    health["hostname"] = hostname
    health["checked_at"] = now_iso()

    # Publish to Redis so the API /health/scanners endpoint can read it
    try:
        r = get_redis_client()
        r.setex(
            f"worker:health:{hostname}",
            3600,  # 1 hour TTL — refreshed on each worker restart
            json.dumps(health),
        )
    except Exception as exc:
        logger.warning(f"Could not publish worker health to Redis: {exc}")

    # Log results prominently
    all_healthy = True
    for name in ("grype", "trivy", "syft"):
        info = health.get(name, {})
        status = info.get("status", "unknown")
        if status == "healthy":
            logger.info(f"  {name}: OK (version: {info.get('version', '?')})")
        elif status == "disabled":
            logger.info(f"  {name}: DISABLED via config")
        else:
            all_healthy = False
            logger.error(
                f"  {name}: UNHEALTHY — {info.get('error', 'unknown')}. "
                "Scans using this scanner will fail until resolved."
            )

    if not all_healthy:
        logger.error(
            "One or more scanners failed preflight. "
            "Scans may return degraded results."
        )


def _extract_packages_from_sbom(sbom_data: dict) -> list:
    """Return a list of {name, version, type, language, licenses} dicts from a
    Syft SBOM, deduplicated by name:version:type. Same shape the SBOM HTML
    template consumes — kept in sync with that template's extraction logic.
    """
    artifacts = sbom_data.get("artifacts", [])
    packages = []
    seen = {}
    for artifact in artifacts:
        licenses = []
        for lic in artifact.get("licenses", []):
            if isinstance(lic, str):
                licenses.append(lic)
            elif isinstance(lic, dict):
                # Syft sometimes stores SPDX expressions in `spdxExpression`
                # and Fedora-style strings in `value`. Prefer SPDX when both.
                licenses.append(
                    lic.get("spdxExpression") or lic.get("value") or "Unknown"
                )

        name = artifact.get("name", "Unknown")
        version = artifact.get("version", "Unknown")
        ptype = artifact.get("type", "Unknown")
        key = f"{name}:{version}:{ptype}"

        if key in seen:
            for lic in licenses:
                if lic not in packages[seen[key]]["licenses"]:
                    packages[seen[key]]["licenses"].append(lic)
            continue

        seen[key] = len(packages)
        packages.append({
            "name": name,
            "version": version,
            "type": ptype,
            "language": artifact.get("language", ""),
            "licenses": licenses,
        })
    return packages


def _format_scan_date() -> str:
    """Render the report's "Scan Date" line as TZ-aware local time.

    `%Z` (timezone name) returns an empty string when TZ is a POSIX-style
    string like `IST-5:30` because Python's strftime reads `time.tzname`,
    which only knows about named timezones from /usr/share/zoneinfo. So we
    use `.astimezone()` to attach the offset, then format with `%z` (which
    always works) and insert a colon so the output looks like:

        2026-06-08 09:24:51 +05:30
    """
    dt = datetime.now().astimezone()
    offset = dt.strftime("%z")  # e.g. "+0530"
    if len(offset) == 5:
        offset = offset[:3] + ":" + offset[3:]  # "+05:30"
    return dt.strftime("%Y-%m-%d %H:%M:%S") + " " + offset


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

        # Extract packages from SBOM, deduplicating by name:version:type.
        # Syft reports the same JAR once per location in the image (e.g. a
        # library bundled inside multiple WARs).  We merge those into a
        # single entry so the HTML report shows unique packages only.
        artifacts = sbom_data.get("artifacts", [])
        packages = []
        package_types = {}
        _seen_pkgs = {}  # key: "name:version:type" -> index in packages

        for artifact in artifacts:
            licenses = []
            for lic in artifact.get("licenses", []):
                if isinstance(lic, str):
                    licenses.append(lic)
                elif isinstance(lic, dict):
                    licenses.append(lic.get("value", "Unknown"))

            pkg_type = artifact.get("type", "Unknown")
            pkg_name = artifact.get("name", "Unknown")
            pkg_version = artifact.get("version", "Unknown")
            dedup_key = f"{pkg_name}:{pkg_version}:{pkg_type}"

            if dedup_key in _seen_pkgs:
                # Merge licenses from duplicate location
                idx = _seen_pkgs[dedup_key]
                for lic in licenses:
                    if lic not in packages[idx]["licenses"]:
                        packages[idx]["licenses"].append(lic)
                continue

            package_types[pkg_type] = package_types.get(pkg_type, 0) + 1
            _seen_pkgs[dedup_key] = len(packages)

            packages.append({
                "name": pkg_name,
                "version": pkg_version,
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
            # Format like "2026-06-08 09:24:51 IST (+05:30)" — works whether TZ
            # is a named zone (Asia/Kolkata) or POSIX (IST-5:30).
            "scan_date": _format_scan_date(),
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

        # Prepare vulnerabilities for display.
        #
        # The report now shows EVERY vulnerability — fixable and not — and the
        # JavaScript filters in the template let users toggle between subsets
        # (Fixable / KEV / High EPSS / Critical+High). We sort by risk so the
        # most urgent items are at the top regardless of the active filter:
        # KEV-listed first, then high EPSS, then severity, then fixability.
        all_vulns = merged_results.get("vulnerabilities", {}).get("all", [])

        severity_order = {
            "CRITICAL": 0, "Critical": 0,
            "HIGH": 1, "High": 1,
            "MEDIUM": 2, "Medium": 2,
            "LOW": 3, "Low": 3,
            "NEGLIGIBLE": 4, "Negligible": 4,
            "UNKNOWN": 5, "Unknown": 5,
        }

        def _risk_sort_key(v):
            sev = severity_order.get(v.get("severity", "Unknown"), 99)
            kev = 0 if v.get("in_kev") or v.get("kev_match") else 1
            epss = -float(v.get("epss_score") or 0)  # higher EPSS first
            fix = 0 if v.get("fix_available") else 1
            return (kev, sev, epss, fix)

        all_vulns_sorted = sorted(all_vulns, key=_risk_sort_key)

        # Subset used by the "Fixable only" toggle (template already has all of them
        # via all_vulnerabilities; we keep this for backwards-compat with the JSON).
        fixable_vulns = [v for v in all_vulns_sorted if v.get("fix_available")]

        # Calculate statistics
        severity_counts = merged_results.get("severity_counts", {})
        fixable_counts = merged_results.get("fixable_counts", {})

        # Risk-intel rollup (used by the summary cards at the top of the report)
        kev_count = sum(1 for v in all_vulns if v.get("in_kev") or v.get("kev_match"))
        high_epss_count = sum(1 for v in all_vulns if float(v.get("epss_score") or 0) >= 0.5)
        risk_priority_counts = {
            "critical": sum(1 for v in all_vulns if v.get("risk_priority") == "critical"),
            "high":     sum(1 for v in all_vulns if v.get("risk_priority") == "high"),
            "medium":   sum(1 for v in all_vulns if v.get("risk_priority") == "medium"),
            "low":      sum(1 for v in all_vulns if v.get("risk_priority") == "low"),
        }

        # Record vulnerability metrics
        for scanner in merged_results.get("scanners_used", []):
            record_vulnerabilities(severity_counts, scanner)

        # Record secret metrics
        secrets = merged_results.get("secrets", [])
        record_secrets(secrets)

        # Get SBOM statistics
        sbom_stats = merged_results.get("sbom", {}).get("statistics", {})

        # Generate report context
        # The primary "vulnerabilities" list is now the FULL list, sorted by
        # risk. The client-side JS filters (defined in the template) toggle
        # visible rows; nothing is hidden server-side.
        report_context = {
            "image_name": image_name,
            "scan_id": scan_id,
            "scan_date": _format_scan_date(),
            "vulnerabilities": all_vulns_sorted,
            "all_vulnerabilities": all_vulns_sorted,
            "severity_counts": severity_counts,
            "fixable_counts": fixable_counts,
            "total_vulnerabilities": len(all_vulns_sorted),
            "total_fixable": len(fixable_vulns),
            "total_non_fixable": len(all_vulns_sorted) - len(fixable_vulns),
            "kev_count": kev_count,
            "high_epss_count": high_epss_count,
            "risk_priority_counts": risk_priority_counts,
            "secrets": secrets,
            "total_secrets": merged_results.get("total_secrets", 0),
            "scanners_used": merged_results.get("scanners_used", []),
            "grype_unique": merged_results.get("grype_unique_count", 0),
            "trivy_unique": merged_results.get("trivy_unique_count", 0),
            "both_scanners": merged_results.get("both_scanners_count", 0),
            "sbom_statistics": sbom_stats,
            # License-compliance summary computed earlier (may be absent if the
            # SBOM couldn't be loaded). The template renders a section when
            # `license_compliance` is truthy.
            "license_compliance": merged_results.get("license_compliance"),
            "scan_summary": {
                "status": "Failed" if (severity_counts.get("Critical", 0) + severity_counts.get("High", 0)) > 0 else "Passed",
                "total_packages": sbom_stats.get("total_packages", 0),
                "scanners": ", ".join(merged_results.get("scanners_used", [])),
                "multi_scanner_validation": len(merged_results.get("scanners_used", [])) > 1,
            },
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
                            cached_data["scan_timestamp"] = now_iso()
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
            scanners_requested = merged_results.get("scanners_requested", [])
            scanners_used = merged_results.get("scanners_used", [])
            scanners_failed = merged_results.get("scanners_failed", {})

            if not scanners_used:
                friendly_summary = summarize_scan_failure(scanners_failed)
                friendly_per_scanner = classify_scanner_errors(scanners_failed)

                # Log the FULL error for ops/support; show the short version to users.
                logger.error(
                    f"All scanners failed: {friendly_summary}",
                    scan_id=scan_id,
                    summary=merged_results.get('summary', {}),
                    raw_errors=scanners_failed,
                )
                redis_client.hset(scan_id, mapping={
                    "status": "failed",
                    "error": friendly_summary,
                    "scanner_errors": json.dumps(friendly_per_scanner),
                    "scanner_errors_raw": json.dumps(scanners_failed),
                })
                SCANS_COMPLETED.labels(status='failure', scanner='all').inc()
                SCANS_IN_PROGRESS.dec()
                return {"scan_id": scan_id, "status": "failed", "error": friendly_summary}

            # Determine scan quality — degraded if some scanners failed
            scan_quality = "full" if set(scanners_requested) == set(scanners_used) else "degraded"
            if scan_quality == "degraded":
                logger.warning(
                    "Scan completed with DEGRADED quality — not all scanners succeeded",
                    scan_id=scan_id,
                    requested=scanners_requested,
                    used=scanners_used,
                    failed=scanners_failed,
                )

            # Guard against false-negative "0 vulns" scans: if BOTH vulnerability
            # scanners (Grype + Trivy) failed and no SBOM was produced, the result
            # is meaningless even though Celery reports the task as completed.
            # Bail out and mark this scan as failed so users don't see green ✅
            # on an image we never actually inspected.
            vuln_scanners_failed = {"grype", "trivy"}.issubset(set(scanners_failed.keys()))
            sbom_packages = merged_results.get("sbom", {}).get("statistics", {}).get("total_packages", 0)
            if vuln_scanners_failed and sbom_packages == 0:
                friendly_summary = summarize_scan_failure(scanners_failed)
                friendly_per_scanner = classify_scanner_errors(scanners_failed)
                logger.error(
                    f"Scan produced no usable data — marking as failed: {friendly_summary}",
                    scan_id=scan_id,
                    raw_errors=scanners_failed,
                )
                redis_client.hset(scan_id, mapping={
                    "status": "failed",
                    "error": friendly_summary,
                    "scanner_errors": json.dumps(friendly_per_scanner),
                    "scanner_errors_raw": json.dumps(scanners_failed),
                })
                SCANS_COMPLETED.labels(status='failure', scanner='all').inc()
                SCANS_IN_PROGRESS.dec()
                return {"scan_id": scan_id, "status": "failed", "error": friendly_summary}

            # Enrich vulnerabilities FIRST (EPSS scores, KEV status, risk_priority)
            # so the HTML report can render these fields. Enrichment is fast
            # (~1s for 5k vulns) and the report is the primary user surface.
            pre_enrich_vulns = merged_results.get("vulnerabilities", {}).get("all", [])
            enriched_vulns, enrichment_summary = enrich_scan_results(pre_enrich_vulns, scan_id)
            merged_results["vulnerabilities"]["all"] = enriched_vulns
            merged_results["enrichment_summary"] = enrichment_summary

            # Run license compliance now (before HTML report) so it can render
            # the new "License Compliance" section. We need the Syft SBOM
            # which has already been written to disk by the syft scanner.
            license_compliance = None
            sbom_data_cached = None
            try:
                syft_json_path = f"{settings.SBOMS_DIR}/{scan_id}_syft_json.json"
                if os.path.exists(syft_json_path):
                    with open(syft_json_path, "r") as f:
                        sbom_data_cached = json.load(f)
                    sbom_packages = _extract_packages_from_sbom(sbom_data_cached)
                    license_compliance = evaluate_licenses(sbom_packages)
                    logger.info(
                        "License compliance evaluated",
                        scan_id=scan_id,
                        status=license_compliance.status,
                        fail=license_compliance.severity_counts.get("fail", 0),
                        warn=license_compliance.severity_counts.get("warn", 0),
                    )
                    redis_client.set(
                        f"licenses:{scan_id}",
                        json.dumps(licenses_to_dict(license_compliance)),
                        ex=settings.SCAN_RESULT_TTL,
                    )
            except Exception as e:
                logger.warning(
                    "License compliance analysis failed",
                    scan_id=scan_id, error=str(e),
                )

            # Stash the compliance result into merged_results so the HTML
            # generator can render it without changing its function signature.
            if license_compliance:
                merged_results["license_compliance"] = licenses_to_dict(license_compliance)

            # Generate enhanced HTML report (now has access to EPSS/KEV/risk_priority + license compliance)
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

            # Generate SBOM HTML report. License compliance already ran above
            # (it has to, so the vuln report can render the new section), so
            # we just reuse the cached SBOM data here when possible.
            sbom_html_report = None
            try:
                sbom_data = sbom_data_cached
                if sbom_data is None:
                    syft_json_path = f"{settings.SBOMS_DIR}/{scan_id}_syft_json.json"
                    if os.path.exists(syft_json_path):
                        with open(syft_json_path, "r") as f:
                            sbom_data = json.load(f)
                if sbom_data is not None:
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

            # Store enriched vulnerabilities (already enriched earlier, before
            # report generation, so the HTML report could render EPSS/KEV).
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

            # Translate any per-scanner failure messages to short, user-friendly
            # text. We keep the raw output in scanner_errors_raw for support.
            friendly_scanner_errors = classify_scanner_errors(scanners_failed)

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

                # Scanner metadata — store BOTH friendly + raw so the dashboard
                # can show a short message but support can still see the full trace.
                "scanners_used": ",".join(scanners_used),
                "scanners_requested": ",".join(scanners_requested),
                "scanner_errors": json.dumps(friendly_scanner_errors),
                "scanner_errors_raw": json.dumps(scanners_failed),
                "scan_quality": scan_quality,
                "scan_timestamp": now_iso(),
                "scan_duration_seconds": duration,

                # EPSS/KEV enrichment data
                "kev_matches": enrichment_summary.get("kev_matches", 0),
                "epss_enriched": enrichment_summary.get("epss_enriched", 0),
                "high_risk_vulns": enrichment_summary.get("high_risk_vulns", 0),
                "image_digest": image_digest or "",
                # License compliance summary — full list is at licenses:<scan_id>
                "license_policy_status": (
                    license_compliance.status if license_compliance else "unknown"
                ),
                "license_policy_fail":   (
                    license_compliance.severity_counts.get("fail", 0)
                    if license_compliance else 0
                ),
                "license_policy_warn":   (
                    license_compliance.severity_counts.get("warn", 0)
                    if license_compliance else 0
                ),
                "license_unknown_count": (
                    license_compliance.counts.get("unknown", 0)
                    if license_compliance else 0
                ),
            }

            redis_client.hset(scan_id, mapping=redis_result)

            # Cache by digest for future identical image scans
            # Only cache full-quality scans — degraded results (scanner failures)
            # should not pollute the cache and block future fresh scans.
            if image_digest and scan_quality == "full":
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
    Dispatch a batch of scans as independent Celery tasks (fire-and-forget).

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
            "Dispatching batch scan",
            batch_id=batch_id,
            image_count=len(images),
        )

        # Dispatch each scan as an independent Celery task.
        #
        # We intentionally do NOT use group(...).get() here — calling .get()
        # from inside a Celery task raises RuntimeError("Never call
        # result.get() within a task!") and can deadlock the worker pool
        # when subtasks land on the same worker that is blocked waiting on
        # them. Instead we fire-and-forget; GET /scan/batch/{batch_id}
        # already aggregates per-scan status by reading each scan_id hash
        # from Redis, so callers see live progress.
        dispatched: List[str] = []
        failed_to_dispatch: List[Dict[str, str]] = []

        for image_name, scan_id in zip(images, scan_ids):
            try:
                scan_image.apply_async(
                    args=[image_name, scan_id],
                    queue="batch",
                    routing_key="batch",
                )
                dispatched.append(scan_id)
            except Exception as e:
                logger.error(
                    "Failed to dispatch scan in batch",
                    batch_id=batch_id,
                    scan_id=scan_id,
                    image=image_name,
                    error=str(e),
                )
                failed_to_dispatch.append({
                    "scan_id": scan_id,
                    "image_name": image_name,
                    "error": str(e),
                })
                # Mark the individual scan hash so the status endpoint
                # surfaces the dispatch failure instead of "in_progress".
                redis_client.hset(scan_id, mapping={
                    "status": "failed",
                    "error": f"Failed to enqueue scan: {e}",
                    "image_name": image_name,
                })

        # Update batch metadata. Per-scan progress is tracked by polling
        # GET /scan/batch/{batch_id} which reads each scan hash directly.
        redis_client.hset(f"batch:{batch_id}", mapping={
            "status": "dispatched",
            "dispatched_count": len(dispatched),
            "dispatch_failed_count": len(failed_to_dispatch),
            "dispatched_at": now_iso(),
        })

        logger.info(
            "Batch scan dispatched",
            batch_id=batch_id,
            dispatched=len(dispatched),
            dispatch_failed=len(failed_to_dispatch),
        )

        return {
            "batch_id": batch_id,
            "status": "dispatched",
            "dispatched": len(dispatched),
            "dispatch_failed": len(failed_to_dispatch),
            "scan_ids": dispatched,
            "errors": failed_to_dispatch,
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
                "created_at": now_iso(),
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
    'update-vulnerability-db-frequent': {
        'task': 'update_vulnerability_databases',
        # Every 3h — Aqua publishes the Trivy DB roughly every 6h and Anchore
        # publishes Grype DB nightly, so 3h is short enough to never miss a
        # publication window. With the shared scanner-cache mount one refresh
        # propagates to every worker automatically.
        'schedule': 10800.0,  # 3 hours in seconds
        'options': {'queue': 'system'},
    },
    'update-kev-database': {
        'task': 'update_kev_database',
        'schedule': 21600.0,  # Every 6 hours (in seconds)
        'options': {'queue': 'system'}  # Must match task_routes config
    },
    'cleanup-old-scan-artifacts': {
        'task': 'cleanup_old_scan_artifacts',
        'schedule': 86400.0,  # Every 24 hours (in seconds)
        'options': {'queue': 'system'}
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
            "timestamp": now_iso()
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
            "timestamp": now_iso()
        }

    except Exception as e:
        logger.error(f"System status check failed: {e}")
        return {
            "error": str(e),
            "timestamp": now_iso()
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
            "timestamp": now_iso()
        }


# ============== Artifact Cleanup Task ==============

@celery.task(bind=True, name='cleanup_old_scan_artifacts')
def cleanup_old_scan_artifacts(self) -> Dict[str, Any]:
    """
    Celery task to clean up old SBOM files and HTML reports.
    Removes files older than ARTIFACT_RETENTION_DAYS (default 7 days).
    Runs daily via beat schedule.
    """
    import glob
    import time

    retention_days = settings.ARTIFACT_RETENTION_DAYS
    cutoff_time = time.time() - (retention_days * 86400)

    logger.info(
        "Starting scan artifact cleanup",
        retention_days=retention_days
    )

    deleted = {"reports": 0, "sboms": 0, "errors": 0}

    for label, directory in [("reports", settings.REPORTS_DIR), ("sboms", settings.SBOMS_DIR)]:
        if not os.path.isdir(directory):
            continue
        for filepath in glob.glob(os.path.join(directory, "*")):
            try:
                if os.path.isfile(filepath) and os.path.getmtime(filepath) < cutoff_time:
                    os.remove(filepath)
                    deleted[label] += 1
            except OSError as e:
                logger.warning(
                    "Failed to delete artifact",
                    path=filepath,
                    error=str(e)
                )
                deleted["errors"] += 1

    logger.info(
        "Artifact cleanup completed",
        deleted_reports=deleted["reports"],
        deleted_sboms=deleted["sboms"],
        errors=deleted["errors"]
    )

    return {
        "status": "completed",
        "retention_days": retention_days,
        "deleted": deleted,
        "timestamp": now_iso()
    }


# ============== IaC Scanning Task ==============

@celery.task(bind=True, name='scan_iac_content', queue='default')
def scan_iac_content(self, content: str, filename: str = "Dockerfile") -> Dict[str, Any]:
    """
    Celery task to scan IaC content for misconfigurations using Trivy.
    Runs on worker which has Trivy installed.
    """
    import subprocess
    import tempfile
    import shutil
    import uuid

    scan_id = str(uuid.uuid4())
    logger.info(f"Starting IaC scan {scan_id} for {filename}")

    try:
        # Create temp directory
        scan_dir = tempfile.mkdtemp(prefix="iac_scan_")
        file_path = os.path.join(scan_dir, filename)

        # Write content to file
        with open(file_path, 'w') as f:
            f.write(content)

        # Run Trivy config scan
        cmd = [
            "trivy", "config",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            scan_dir
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse output
        output = result.stdout or result.stderr

        try:
            if "{" in output:
                json_start = output.index("{")
                scan_data = json.loads(output[json_start:])
            else:
                scan_data = {"Results": []}
        except json.JSONDecodeError:
            scan_data = {"Results": []}

        # Process results
        findings = []
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        files_scanned = 0

        for result_item in scan_data.get("Results", []):
            files_scanned += 1
            target_file = result_item.get("Target", "unknown")

            for misconfig in result_item.get("Misconfigurations", []):
                severity = misconfig.get("Severity", "UNKNOWN").lower()
                if severity in summary:
                    summary[severity] += 1

                cause = misconfig.get("CauseMetadata", {})
                code_lines = cause.get("Code", {}).get("Lines", [])
                code_snippet = None
                if code_lines:
                    code_snippet = "\n".join([
                        line.get("Content", "") for line in code_lines
                    ])

                finding = {
                    "id": misconfig.get("ID", ""),
                    "avd_id": misconfig.get("AVDID", ""),
                    "title": misconfig.get("Title", ""),
                    "description": misconfig.get("Description", ""),
                    "message": misconfig.get("Message", ""),
                    "severity": misconfig.get("Severity", "UNKNOWN"),
                    "resolution": misconfig.get("Resolution", ""),
                    "file": target_file,
                    "start_line": cause.get("StartLine", 0),
                    "end_line": cause.get("EndLine", 0),
                    "code_snippet": code_snippet,
                    "primary_url": misconfig.get("PrimaryURL", ""),
                    "references": misconfig.get("References", [])
                }
                findings.append(finding)

        logger.info(
            f"IaC scan {scan_id} completed",
            findings_count=len(findings),
            summary=summary
        )

        return {
            "scan_id": scan_id,
            "status": "completed",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "source": f"file:{filename}",
            "files_scanned": files_scanned,
            "summary": summary,
            "findings": findings,
            "error": None
        }

    except subprocess.TimeoutExpired:
        logger.error(f"IaC scan {scan_id} timed out")
        return {
            "scan_id": scan_id,
            "status": "failed",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "source": f"file:{filename}",
            "files_scanned": 0,
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
            "error": "Scan timed out after 300 seconds"
        }

    except Exception as e:
        logger.error(f"IaC scan {scan_id} failed: {e}")
        return {
            "scan_id": scan_id,
            "status": "failed",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "source": f"file:{filename}",
            "files_scanned": 0,
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
            "error": str(e)
        }

    finally:
        # Cleanup
        if 'scan_dir' in locals() and os.path.exists(scan_dir):
            shutil.rmtree(scan_dir, ignore_errors=True)
