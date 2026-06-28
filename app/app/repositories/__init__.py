"""Data-access repositories (Phase 0 of the Postgres migration).

All durable-data access is being funneled through repositories so the
storage backend is swappable in one place. In Phase 0 these wrap the existing
Redis calls verbatim — no behaviour change — and become the seam where later
phases introduce Postgres (dual-write, then read-cutover).
"""
from app.repositories.scan_repository import ScanRepository
from app.repositories.batch_repository import BatchRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository

__all__ = ["ScanRepository", "BatchRepository", "VulnerabilityRepository"]
