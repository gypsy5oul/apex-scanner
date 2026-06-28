"""ORM models for the durable domains (Phase 1 schema).

These mirror what the repositories persist to Redis today; Phase 2 dual-writes
into these tables. Typed columns for what we query/filter; JSONB for the long
tail. ``Optional`` (not ``X | None``) is used deliberately so the models import
under the py3.9 test interpreter as well as the py3.12 runtime.
"""
from datetime import datetime
from typing import Optional, Any, List, Dict

from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    image_name: Mapped[Optional[str]] = mapped_column(String(512), index=True)
    status: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    scan_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    negligible: Mapped[int] = mapped_column(Integer, default=0)
    unknown: Mapped[int] = mapped_column(Integer, default=0)
    total_packages: Mapped[int] = mapped_column(Integer, default=0)
    total_secrets: Mapped[int] = mapped_column(Integer, default=0)
    report_url: Mapped[Optional[str]] = mapped_column(Text)
    sbom_report_url: Mapped[Optional[str]] = mapped_column(Text)
    image_digest: Mapped[Optional[str]] = mapped_column(String(256))
    scan_quality: Mapped[Optional[str]] = mapped_column(String(32))
    batch_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    detail: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    package_name: Mapped[Optional[str]] = mapped_column(String(512))
    package_version: Mapped[Optional[str]] = mapped_column(String(256))
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    epss_score: Mapped[Optional[float]] = mapped_column(Float)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    fix_available: Mapped[bool] = mapped_column(Boolean, default=False)
    data: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)


class Batch(Base):
    __tablename__ = "batches"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)
    total_images: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[Optional[str]] = mapped_column(String(32))
    image_list: Mapped[List[Any]] = mapped_column(JSONB, default=list)


class License(Base):
    __tablename__ = "licenses"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[Optional[str]] = mapped_column(String(32))
    data: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(128))
    target: Mapped[Optional[str]] = mapped_column(String(256))
    ip: Mapped[Optional[str]] = mapped_column(String(64))
    detail: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)


class KvSetting(Base):
    __tablename__ = "kv_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
