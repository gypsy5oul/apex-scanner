"""Phase 2: dual-write mappers (pure Redis-shape -> table-row) are correct.

These run in the py3.9 test env WITHOUT sqlalchemy/psycopg — the mappers import
nothing DB-related. The upsert_* I/O is validated live (DATABASE_URL is unset in
tests, so the repository dual-write hooks are no-ops here)."""
from datetime import datetime
from app.db.dual_write import scan_row, batch_row, license_row, vuln_row


def test_scan_row_typed_and_detail():
    h = {"image_name": "img:a", "status": "completed", "created_by": "alice",
         "critical": "3", "high": "5", "total_packages": "120",
         "scan_timestamp": "2026-06-28T04:00:00+00:00", "report_url": "https://r/x.html",
         "batch_id": "b1", "sbom_urls": "{}"}
    row = scan_row("s1", h)
    assert row["id"] == "s1"
    assert row["critical"] == 3 and row["high"] == 5 and row["total_packages"] == 120
    assert isinstance(row["scan_timestamp"], datetime)
    assert row["created_by"] == "alice" and row["batch_id"] == "b1"
    assert row["detail"] == h            # full hash preserved in JSONB
    # empty/missing coerce safely
    assert scan_row("s2", {})["critical"] == 0
    assert scan_row("s2", {})["report_url"] is None


def test_batch_row_parses_images():
    row = batch_row("b1", {"created_by": "bob", "total_images": "2",
                           "status": "in_progress", "images": '["nginx:1","redis:7"]'})
    assert row["id"] == "b1" and row["total_images"] == 2
    assert row["image_list"] == ["nginx:1", "redis:7"]


def test_license_row_keeps_full_data():
    data = {"status": "pass", "fail": 0, "licenses": ["MIT"]}
    row = license_row("s1", data)
    assert row["scan_id"] == "s1" and row["status"] == "pass" and row["data"] == data


def test_vuln_row_field_aliases():
    row = vuln_row("s1", {"id": "CVE-2024-1", "severity": "high", "package": "openssl",
                          "version": "1.1", "epss": "0.42", "kev": "true", "fixed_version": "1.2"})
    assert row["scan_id"] == "s1" and row["cve_id"] == "CVE-2024-1"
    assert row["package_name"] == "openssl" and row["package_version"] == "1.1"
    assert row["epss_score"] == 0.42 and row["in_kev"] is True and row["fix_available"] is True
