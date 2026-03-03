"""
Tests for scanner parsers and orchestrator merge/dedup logic.
"""
import json
import pytest
from unittest.mock import patch, MagicMock

from app.scanners.grype_scanner import GrypeScanner
from app.scanners.trivy_scanner import TrivyScanner
from app.scanners.orchestrator import ScannerOrchestrator


class TestGrypeParser:
    """Tests for Grype output parsing."""

    def setup_method(self):
        self.scanner = GrypeScanner()

    def test_parse_valid_output(self, sample_grype_output):
        """Grype parser should extract vulnerabilities from valid JSON."""
        raw = json.dumps(sample_grype_output)
        result = self.scanner.parse_results(raw)

        assert len(result["vulnerabilities"]) == 3
        assert result["total_vulnerabilities"] == 3

    def test_parse_vulnerability_fields(self, sample_grype_output):
        """Parsed vulnerabilities should contain all expected fields."""
        raw = json.dumps(sample_grype_output)
        result = self.scanner.parse_results(raw)
        vuln = result["vulnerabilities"][0]

        assert vuln["id"] == "CVE-2024-1234"
        assert vuln["severity"] == "Critical"
        assert vuln["package_name"] == "openssl"
        assert vuln["package_version"] == "1.1.1k"
        assert vuln["package_type"] == "deb"
        assert vuln["cvss_score"] == 9.8
        assert vuln["fix_available"] is True
        assert vuln["fix_versions"] == ["1.2.4"]
        assert vuln["source"] == "grype"

    def test_parse_no_fix_available(self, sample_grype_output):
        """Vulnerability with no fix versions should show fix_available=False."""
        raw = json.dumps(sample_grype_output)
        result = self.scanner.parse_results(raw)

        # CVE-2024-5678 has empty fix versions
        curl_vuln = next(v for v in result["vulnerabilities"] if v["id"] == "CVE-2024-5678")
        assert curl_vuln["fix_available"] is False
        assert curl_vuln["fix_versions"] == []

    def test_parse_severity_counts(self, sample_grype_output):
        """Severity counts should be calculated correctly."""
        raw = json.dumps(sample_grype_output)
        result = self.scanner.parse_results(raw)

        assert result["severity_counts"]["Critical"] == 1
        assert result["severity_counts"]["High"] == 1
        assert result["severity_counts"]["Low"] == 1
        assert result["severity_counts"]["Medium"] == 0

    def test_parse_empty_matches(self):
        """Empty matches list should produce zero vulnerabilities."""
        raw = json.dumps({"matches": [], "descriptor": {"name": "grype"}})
        result = self.scanner.parse_results(raw)

        assert result["vulnerabilities"] == []
        assert result["total_vulnerabilities"] == 0

    def test_parse_invalid_json(self):
        """Invalid JSON should return empty results with error."""
        result = self.scanner.parse_results("not valid json {{{")

        assert result["vulnerabilities"] == []
        assert result["total_vulnerabilities"] == 0
        assert "error" in result

    def test_parse_missing_fields(self):
        """Missing fields in matches should use defaults."""
        raw = json.dumps({
            "matches": [{"vulnerability": {}, "artifact": {}}],
            "descriptor": {"name": "grype"}
        })
        result = self.scanner.parse_results(raw)

        vuln = result["vulnerabilities"][0]
        assert vuln["id"] == "N/A"
        assert vuln["severity"] == "Unknown"
        assert vuln["package_name"] == "Unknown"
        assert vuln["cvss_score"] == "N/A"


class TestTrivyParser:
    """Tests for Trivy output parsing."""

    def setup_method(self):
        self.scanner = TrivyScanner()

    def test_parse_valid_output(self, sample_trivy_output):
        """Trivy parser should extract vulnerabilities and secrets."""
        raw = json.dumps(sample_trivy_output)
        result = self.scanner.parse_results(raw)

        assert len(result["vulnerabilities"]) == 2
        assert len(result["secrets"]) == 1
        assert result["total_vulnerabilities"] == 2
        assert result["total_secrets"] == 1

    def test_parse_vulnerability_fields(self, sample_trivy_output):
        """Parsed Trivy vulnerabilities should contain expected fields."""
        raw = json.dumps(sample_trivy_output)
        result = self.scanner.parse_results(raw)
        vuln = result["vulnerabilities"][0]

        assert vuln["id"] == "CVE-2024-1234"
        assert vuln["severity"] == "CRITICAL"
        assert vuln["package_name"] == "openssl"
        assert vuln["package_version"] == "1.1.1k"
        assert vuln["fix_available"] is True
        assert vuln["fix_versions"] == ["1.1.1l"]
        assert vuln["source"] == "trivy"

    def test_parse_cvss_extraction(self, sample_trivy_output):
        """CVSS score should be extracted from NVD data."""
        raw = json.dumps(sample_trivy_output)
        result = self.scanner.parse_results(raw)

        openssl = result["vulnerabilities"][0]
        assert openssl["cvss_score"] == "9.8"

    def test_parse_cvss_missing(self, sample_trivy_output):
        """Missing CVSS should return N/A."""
        raw = json.dumps(sample_trivy_output)
        result = self.scanner.parse_results(raw)

        libxml = result["vulnerabilities"][1]
        assert libxml["cvss_score"] == "N/A"

    def test_parse_secret_fields(self, sample_trivy_output):
        """Parsed secrets should contain expected fields."""
        raw = json.dumps(sample_trivy_output)
        result = self.scanner.parse_results(raw)
        secret = result["secrets"][0]

        assert secret["rule_id"] == "aws-access-key-id"
        assert secret["category"] == "AWS"
        assert secret["severity"] == "CRITICAL"
        assert secret["line"] == 42

    def test_parse_severity_counts_uppercase(self, sample_trivy_output):
        """Trivy severity counts use UPPERCASE format."""
        raw = json.dumps(sample_trivy_output)
        result = self.scanner.parse_results(raw)

        assert result["severity_counts"]["Critical"] == 1
        assert result["severity_counts"]["Medium"] == 1

    def test_parse_empty_results(self):
        """Empty Results should produce zero vulnerabilities."""
        raw = json.dumps({"Results": []})
        result = self.scanner.parse_results(raw)

        assert result["vulnerabilities"] == []
        assert result["secrets"] == []

    def test_parse_invalid_json(self):
        """Invalid JSON should return empty results with error."""
        result = self.scanner.parse_results("<<<invalid>>>")

        assert result["vulnerabilities"] == []
        assert result["secrets"] == []
        assert "error" in result

    def test_extract_cvss_vendor_fallback(self):
        """CVSS extraction should fall back to non-NVD vendor data."""
        vuln = {
            "CVSS": {
                "redhat": {"V3Score": 7.2}
            }
        }
        score = self.scanner._extract_cvss(vuln)
        assert score == "7.2"

    def test_extract_cvss_non_dict(self):
        """Non-dict CVSS should return N/A."""
        vuln = {"CVSS": "not a dict"}
        score = self.scanner._extract_cvss(vuln)
        assert score == "N/A"


class TestOrchestratorDeduplication:
    """Tests for the orchestrator's deduplication logic."""

    def setup_method(self):
        """Create orchestrator with all scanners disabled to skip preflight."""
        with patch("app.scanners.orchestrator.GrypeScanner"), \
             patch("app.scanners.orchestrator.TrivyScanner"), \
             patch("app.scanners.orchestrator.SyftScanner"):
            with patch("app.config.settings") as mock_settings:
                mock_settings.ENABLE_GRYPE = False
                mock_settings.ENABLE_TRIVY = False
                mock_settings.ENABLE_SYFT = False
                self.orchestrator = ScannerOrchestrator()

    def test_dedup_both_scanners(self):
        """Vulnerabilities found by both scanners should be merged."""
        grype_vulns = [
            {"id": "CVE-2024-1234", "package_name": "openssl", "severity": "Critical", "source": "grype"}
        ]
        trivy_vulns = [
            {"id": "CVE-2024-1234", "package_name": "openssl", "severity": "CRITICAL", "source": "trivy"}
        ]

        result = self.orchestrator._deduplicate_vulnerabilities(grype_vulns, trivy_vulns)

        assert len(result["all"]) == 1
        assert len(result["by_source"]["both_scanners"]) == 1
        assert result["all"][0]["found_by"] == ["grype", "trivy"]
        assert result["all"][0]["confidence"] == "high"

    def test_dedup_grype_only(self):
        """Vulnerabilities found only by Grype should be marked as medium confidence."""
        grype_vulns = [
            {"id": "CVE-2024-1111", "package_name": "curl", "severity": "High", "source": "grype"}
        ]
        trivy_vulns = []

        result = self.orchestrator._deduplicate_vulnerabilities(grype_vulns, trivy_vulns)

        assert len(result["by_source"]["grype_only"]) == 1
        assert result["all"][0]["found_by"] == ["grype"]
        assert result["all"][0]["confidence"] == "medium"

    def test_dedup_trivy_only(self):
        """Vulnerabilities found only by Trivy should be marked as medium confidence."""
        grype_vulns = []
        trivy_vulns = [
            {"id": "CVE-2024-2222", "package_name": "libxml2", "severity": "MEDIUM", "source": "trivy"}
        ]

        result = self.orchestrator._deduplicate_vulnerabilities(grype_vulns, trivy_vulns)

        assert len(result["by_source"]["trivy_only"]) == 1
        assert result["all"][0]["found_by"] == ["trivy"]
        assert result["all"][0]["confidence"] == "medium"

    def test_dedup_key_includes_package(self):
        """Same CVE in different packages should NOT be deduplicated."""
        grype_vulns = [
            {"id": "CVE-2024-1234", "package_name": "openssl", "severity": "Critical", "source": "grype"},
            {"id": "CVE-2024-1234", "package_name": "libssl", "severity": "Critical", "source": "grype"},
        ]
        trivy_vulns = []

        result = self.orchestrator._deduplicate_vulnerabilities(grype_vulns, trivy_vulns)
        assert len(result["all"]) == 2

    def test_dedup_empty_inputs(self):
        """Both empty inputs should return empty results."""
        result = self.orchestrator._deduplicate_vulnerabilities([], [])

        assert result["all"] == []
        assert result["by_source"]["grype_only"] == []
        assert result["by_source"]["trivy_only"] == []
        assert result["by_source"]["both_scanners"] == []


class TestSeverityCounts:
    """Tests for severity count calculations."""

    def setup_method(self):
        with patch("app.scanners.orchestrator.GrypeScanner"), \
             patch("app.scanners.orchestrator.TrivyScanner"), \
             patch("app.scanners.orchestrator.SyftScanner"):
            with patch("app.config.settings") as mock_settings:
                mock_settings.ENABLE_GRYPE = False
                mock_settings.ENABLE_TRIVY = False
                mock_settings.ENABLE_SYFT = False
                self.orchestrator = ScannerOrchestrator()

    def test_severity_normalization(self):
        """Both UPPERCASE and Title Case severities should be counted correctly."""
        vulns = [
            {"severity": "CRITICAL"},
            {"severity": "Critical"},
            {"severity": "HIGH"},
            {"severity": "High"},
            {"severity": "MEDIUM"},
            {"severity": "Low"},
        ]

        counts = self.orchestrator._calculate_severity_counts(vulns)
        assert counts["Critical"] == 2
        assert counts["High"] == 2
        assert counts["Medium"] == 1
        assert counts["Low"] == 1

    def test_unknown_severity(self):
        """Unknown or missing severity should be counted as Unknown."""
        vulns = [
            {"severity": "Unknown"},
            {"severity": "UNKNOWN"},
            {},
        ]

        counts = self.orchestrator._calculate_severity_counts(vulns)
        assert counts["Unknown"] == 3

    def test_fixable_counts(self):
        """Fixable counts should only include vulnerabilities with fix_available=True."""
        vulns = [
            {"severity": "Critical", "fix_available": True},
            {"severity": "Critical", "fix_available": False},
            {"severity": "High", "fix_available": True},
            {"severity": "Low", "fix_available": False},
        ]

        counts = self.orchestrator._calculate_fixable_counts(vulns)
        assert counts["total"] == 2
        assert counts["Critical"] == 1
        assert counts["High"] == 1
        assert counts["Low"] == 0


class TestMergeResults:
    """Tests for the full merge_results method."""

    def setup_method(self):
        with patch("app.scanners.orchestrator.GrypeScanner"), \
             patch("app.scanners.orchestrator.TrivyScanner"), \
             patch("app.scanners.orchestrator.SyftScanner"):
            with patch("app.config.settings") as mock_settings:
                mock_settings.ENABLE_GRYPE = False
                mock_settings.ENABLE_TRIVY = False
                mock_settings.ENABLE_SYFT = False
                self.orchestrator = ScannerOrchestrator()

    def test_merge_both_success(self):
        """Successful results from both scanners should be merged."""
        grype_result = {
            "success": True,
            "total_vulnerabilities": 1,
            "vulnerabilities": [
                {"id": "CVE-2024-1234", "package_name": "openssl", "severity": "Critical"}
            ]
        }
        trivy_result = {
            "success": True,
            "total_vulnerabilities": 1,
            "vulnerabilities": [
                {"id": "CVE-2024-1234", "package_name": "openssl", "severity": "CRITICAL"}
            ],
            "secrets": [{"rule_id": "test-secret"}]
        }
        syft_result = {"success": False, "error": "disabled"}

        merged = self.orchestrator.merge_results(grype_result, trivy_result, syft_result, "scan-123")

        assert "grype" in merged["scanners_used"]
        assert "trivy" in merged["scanners_used"]
        assert merged["total_unique_vulnerabilities"] == 1
        assert merged["both_scanners_count"] == 1
        assert merged["total_secrets"] == 1

    def test_merge_grype_failed(self):
        """Failed Grype should still include Trivy results."""
        grype_result = {"success": False, "error": "Grype binary not found"}
        trivy_result = {
            "success": True,
            "total_vulnerabilities": 2,
            "vulnerabilities": [
                {"id": "CVE-1", "package_name": "pkg1", "severity": "HIGH"},
                {"id": "CVE-2", "package_name": "pkg2", "severity": "MEDIUM"},
            ],
            "secrets": []
        }
        syft_result = {"success": False, "error": "disabled"}

        merged = self.orchestrator.merge_results(grype_result, trivy_result, syft_result, "scan-456")

        assert "grype" not in merged["scanners_used"]
        assert "trivy" in merged["scanners_used"]
        assert merged["total_unique_vulnerabilities"] == 2
        assert merged["trivy_unique_count"] == 2

    def test_merge_both_failed(self):
        """Both scanners failing should produce zero vulnerabilities."""
        grype_result = {"success": False, "error": "fail"}
        trivy_result = {"success": False, "error": "fail"}
        syft_result = {"success": False, "error": "fail"}

        merged = self.orchestrator.merge_results(grype_result, trivy_result, syft_result, "scan-789")

        assert merged["scanners_used"] == []
        assert merged["total_unique_vulnerabilities"] == 0

    def test_merge_syft_success(self):
        """Successful Syft should be included in scanners_used."""
        grype_result = {"success": False, "error": "disabled"}
        trivy_result = {"success": False, "error": "disabled"}
        syft_result = {
            "syft-json": {"success": True},
            "statistics": {"total_packages": 150}
        }

        merged = self.orchestrator.merge_results(grype_result, trivy_result, syft_result, "scan-sbom")

        assert "syft" in merged["scanners_used"]
        assert merged["sbom"]["statistics"]["total_packages"] == 150


class TestRetryLogic:
    """Tests for the _run_with_retry static method."""

    def test_success_on_first_attempt(self):
        """Successful first attempt should return immediately."""
        fn = MagicMock(return_value={"success": True, "data": "test"})

        result = ScannerOrchestrator._run_with_retry(fn, ("arg1",), "test-scanner", max_retries=2)

        assert result["success"] is True
        assert result["attempts"] == 1
        fn.assert_called_once()

    def test_success_on_retry(self):
        """Should succeed after retries."""
        fn = MagicMock(side_effect=[
            {"success": False, "error": "transient"},
            {"success": True, "data": "recovered"},
        ])

        result = ScannerOrchestrator._run_with_retry(fn, ("arg1",), "test-scanner", max_retries=2)

        assert result["success"] is True
        assert result["attempts"] == 2

    def test_all_retries_exhausted(self):
        """All attempts failing should return last failure."""
        fn = MagicMock(return_value={"success": False, "error": "permanent"})

        result = ScannerOrchestrator._run_with_retry(fn, ("arg1",), "test-scanner", max_retries=0)

        assert result["success"] is False
        assert result["attempts"] == 1

    def test_exception_handling(self):
        """Exceptions should be caught and reported."""
        fn = MagicMock(side_effect=RuntimeError("boom"))

        result = ScannerOrchestrator._run_with_retry(fn, ("arg1",), "test-scanner", max_retries=0)

        assert result["success"] is False
        assert "exception" in result["error"]
