"""
Custom Prometheus metrics for the security scanner
"""
from prometheus_client import Counter, Histogram, Gauge, Info
import time
from functools import wraps
from typing import Callable, Any


# Application info
APP_INFO = Info(
    'scanner_app',
    'Security scanner application information'
)
APP_INFO.info({
    'version': '2.0.0',
    'scanners': 'grype,trivy,syft'
})

# Scan metrics
SCANS_TOTAL = Counter(
    'scanner_scans_total',
    'Total number of scans initiated',
    ['image_registry', 'scan_type']
)

SCANS_COMPLETED = Counter(
    'scanner_scans_completed_total',
    'Total number of scans completed',
    ['status', 'scanner']
)

SCANS_IN_PROGRESS = Gauge(
    'scanner_scans_in_progress',
    'Number of scans currently in progress'
)

SCAN_DURATION = Histogram(
    'scanner_scan_duration_seconds',
    'Duration of scan operations',
    ['scanner'],
    buckets=[10, 30, 60, 120, 180, 300, 600, 900, 1800]
)

# Vulnerability metrics
VULNERABILITIES_FOUND = Counter(
    'scanner_vulnerabilities_found_total',
    'Total vulnerabilities found across all scans',
    ['severity', 'scanner']
)

VULNERABILITIES_BY_SCAN = Histogram(
    'scanner_vulnerabilities_per_scan',
    'Distribution of vulnerabilities per scan',
    ['severity'],
    buckets=[0, 1, 5, 10, 25, 50, 100, 250, 500, 1000]
)

SECRETS_FOUND = Counter(
    'scanner_secrets_found_total',
    'Total secrets detected across all scans',
    ['category']
)

# SBOM metrics
PACKAGES_FOUND = Counter(
    'scanner_packages_found_total',
    'Total packages found in SBOMs',
    ['package_type']
)

SBOM_GENERATION_DURATION = Histogram(
    'scanner_sbom_generation_seconds',
    'Duration of SBOM generation',
    ['format'],
    buckets=[5, 10, 30, 60, 120, 300]
)

# API metrics
API_REQUESTS = Counter(
    'scanner_api_requests_total',
    'Total API requests',
    ['endpoint', 'method', 'status_code']
)

API_REQUEST_DURATION = Histogram(
    'scanner_api_request_duration_seconds',
    'API request duration',
    ['endpoint', 'method'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

# Queue metrics
QUEUE_SIZE = Gauge(
    'scanner_queue_size',
    'Number of tasks in the queue'
)

QUEUE_WAIT_TIME = Histogram(
    'scanner_queue_wait_seconds',
    'Time tasks spend waiting in queue',
    buckets=[1, 5, 10, 30, 60, 120, 300, 600]
)

# Worker metrics
WORKERS_ACTIVE = Gauge(
    'scanner_workers_active',
    'Number of active workers'
)

WORKER_TASKS_PROCESSED = Counter(
    'scanner_worker_tasks_processed_total',
    'Total tasks processed by workers',
    ['worker_id', 'task_type']
)

# Redis metrics
REDIS_OPERATIONS = Counter(
    'scanner_redis_operations_total',
    'Total Redis operations',
    ['operation', 'status']
)

REDIS_OPERATION_DURATION = Histogram(
    'scanner_redis_operation_seconds',
    'Redis operation duration',
    ['operation'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
)

# Batch scan metrics
BATCH_SCANS_TOTAL = Counter(
    'scanner_batch_scans_total',
    'Total batch scan requests'
)

BATCH_SIZE = Histogram(
    'scanner_batch_size',
    'Number of images per batch scan',
    buckets=[1, 2, 5, 10, 20, 50, 100]
)


def track_scan_duration(scanner_name: str):
    """Decorator to track scan duration"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                SCANS_COMPLETED.labels(status='success', scanner=scanner_name).inc()
                return result
            except Exception as e:
                SCANS_COMPLETED.labels(status='failure', scanner=scanner_name).inc()
                raise
            finally:
                duration = time.time() - start_time
                SCAN_DURATION.labels(scanner=scanner_name).observe(duration)
        return wrapper
    return decorator


def track_api_request(endpoint: str, method: str):
    """Decorator to track API request metrics"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                status_code = getattr(result, 'status_code', 200)
                API_REQUESTS.labels(
                    endpoint=endpoint,
                    method=method,
                    status_code=str(status_code)
                ).inc()
                return result
            except Exception as e:
                API_REQUESTS.labels(
                    endpoint=endpoint,
                    method=method,
                    status_code='500'
                ).inc()
                raise
            finally:
                duration = time.time() - start_time
                API_REQUEST_DURATION.labels(
                    endpoint=endpoint,
                    method=method
                ).observe(duration)
        return wrapper
    return decorator


def record_vulnerabilities(severity_counts: dict, scanner: str):
    """Record vulnerability counts from a scan"""
    for severity, count in severity_counts.items():
        if count > 0:
            VULNERABILITIES_FOUND.labels(
                severity=severity.lower(),
                scanner=scanner
            ).inc(count)
            VULNERABILITIES_BY_SCAN.labels(
                severity=severity.lower()
            ).observe(count)


def record_secrets(secrets: list):
    """Record secret detections"""
    for secret in secrets:
        category = secret.get('category', 'unknown')
        SECRETS_FOUND.labels(category=category).inc()


def record_packages(package_types: dict):
    """Record package counts from SBOM"""
    for pkg_type, count in package_types.items():
        if count > 0:
            PACKAGES_FOUND.labels(package_type=pkg_type).inc(count)


def extract_registry(image_name: str) -> str:
    """Extract registry from image name"""
    if '/' not in image_name:
        return 'docker.io'
    parts = image_name.split('/')
    if '.' in parts[0] or ':' in parts[0]:
        return parts[0]
    return 'docker.io'
