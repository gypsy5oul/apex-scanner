"""
Tests for the enrichment module: DigestCache, EPSSClient, KEVClient, VulnerabilityEnricher.
"""
import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from app.enrichment import (
    EPSSClient,
    KEVClient,
    DigestCache,
    VulnerabilityEnricher,
    check_digest_cache,
    cache_scan_by_digest,
)


class TestEPSSClient:
    """Tests for EPSS score fetching and caching."""

    def test_empty_cve_list(self, mock_redis):
        """Empty CVE list should return empty dict."""
        client = EPSSClient()
        result = client.get_epss_scores([])
        assert result == {}

    def test_non_cve_ids_filtered(self, mock_redis):
        """Non-CVE IDs should be filtered out."""
        client = EPSSClient()
        result = client.get_epss_scores(["NOT-A-CVE", "RANDOM-123"])
        assert result == {}

    def test_cached_results_returned(self, mock_redis):
        """Cached EPSS scores should be returned without API call."""
        cached_data = {"epss_score": 0.85, "epss_percentile": 0.95, "epss_date": "2024-01-01"}
        mock_redis.set("epss:CVE-2024-1234", json.dumps(cached_data))

        client = EPSSClient()
        # Patch _fetch_epss_batch to ensure we don't call the API
        with patch.object(client, "_fetch_epss_batch", return_value={}) as mock_fetch:
            result = client.get_epss_scores(["CVE-2024-1234"])
            mock_fetch.assert_not_called()

        assert "CVE-2024-1234" in result
        assert result["CVE-2024-1234"]["epss_score"] == 0.85

    def test_fetch_from_api(self, mock_redis):
        """Uncached CVEs should be fetched from EPSS API."""
        client = EPSSClient()
        batch_result = {
            "CVE-2024-5678": {"epss_score": 0.42, "epss_percentile": 0.88, "epss_date": "2024-06-01"}
        }

        with patch.object(client, "_fetch_epss_batch", return_value=batch_result):
            result = client.get_epss_scores(["CVE-2024-5678"])

        assert "CVE-2024-5678" in result
        assert result["CVE-2024-5678"]["epss_score"] == 0.42

    @patch("app.enrichment.httpx.Client")
    def test_api_error_returns_empty(self, mock_httpx_class, mock_redis):
        """API errors should return empty results, not raise."""
        import httpx
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.HTTPError("Connection failed")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_httpx_class.return_value = mock_client

        client = EPSSClient()
        result = client._fetch_epss_batch(["CVE-2024-9999"])

        assert result == {}

    def test_get_single_score(self, mock_redis):
        """get_single_score should return data for a single CVE."""
        cached_data = {"epss_score": 0.5, "epss_percentile": 0.7, "epss_date": "2024-01-01"}
        mock_redis.set("epss:CVE-2024-1234", json.dumps(cached_data))

        client = EPSSClient()
        with patch.object(client, "_fetch_epss_batch", return_value={}):
            result = client.get_single_score("CVE-2024-1234")

        assert result is not None
        assert result["epss_score"] == 0.5

    def test_get_single_score_not_found(self, mock_redis):
        """get_single_score for non-existent CVE should return None."""
        client = EPSSClient()

        with patch.object(client, "_fetch_epss_batch", return_value={}):
            result = client.get_single_score("CVE-9999-0000")
            assert result is None


class TestKEVClient:
    """Tests for KEV catalog integration."""

    def test_is_in_kev_empty(self, mock_redis):
        """Empty CVE ID should return False."""
        client = KEVClient()
        assert client.is_in_kev("") is False

    def test_is_in_kev_found(self, mock_redis):
        """CVE in the KEV set should return True."""
        mock_redis.sadd("kev:cve_set", "CVE-2024-1234")

        client = KEVClient()
        assert bool(client.is_in_kev("CVE-2024-1234")) is True

    def test_is_in_kev_not_found(self, mock_redis):
        """CVE not in the KEV set should return False."""
        client = KEVClient()
        assert bool(client.is_in_kev("CVE-9999-0000")) is False

    def test_check_cves_batch(self, mock_redis):
        """Batch check should return dict of CVE -> bool."""
        mock_redis.sadd("kev:cve_set", "CVE-2024-1111", "CVE-2024-3333")

        client = KEVClient()
        result = client.check_cves(["CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333"])

        assert result["CVE-2024-1111"] is True
        assert result["CVE-2024-2222"] is False
        assert result["CVE-2024-3333"] is True

    def test_check_cves_empty(self, mock_redis):
        """Empty CVE list should return empty dict."""
        client = KEVClient()
        assert client.check_cves([]) == {}

    def test_get_kev_details(self, mock_redis):
        """Should retrieve detailed KEV entry."""
        mock_redis.sadd("kev:cve_set", "CVE-2024-1234")
        kev_data = {
            "vulnerabilities": [{
                "cveID": "CVE-2024-1234",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "RCE via JNDI",
                "dateAdded": "2024-01-01",
                "shortDescription": "Critical RCE",
                "requiredAction": "Apply update",
                "dueDate": "2024-02-01",
                "knownRansomwareCampaignUse": "Known"
            }]
        }
        mock_redis.setex("kev:catalog", 43200, json.dumps(kev_data))

        client = KEVClient()
        details = client.get_kev_details("CVE-2024-1234")

        assert details is not None
        assert details["vendor"] == "Apache"
        assert details["product"] == "Log4j"
        assert details["known_ransomware_use"] == "Known"

    def test_get_kev_details_not_in_kev(self, mock_redis):
        """Non-KEV CVE should return None."""
        client = KEVClient()
        assert client.get_kev_details("CVE-9999-0000") is None

    def test_get_kev_stats(self, mock_redis):
        """Stats should return total count and TTL."""
        mock_redis.sadd("kev:cve_set", "CVE-1", "CVE-2", "CVE-3")
        mock_redis.set("kev:last_update", "2024-01-01T00:00:00")

        client = KEVClient()
        stats = client.get_kev_stats()

        assert stats["total_kev_cves"] == 3
        assert stats["last_update"] == "2024-01-01T00:00:00"
        assert stats["cache_ttl_hours"] == 12


class TestDigestCache:
    """Tests for the image digest cache."""

    def test_digest_pinned_image(self, mock_redis):
        """Images pinned by digest should return the digest directly."""
        cache = DigestCache()
        digest = cache.get_image_digest("nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        assert digest == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

    @patch("app.enrichment.subprocess.run")
    def test_skopeo_success(self, mock_run, mock_redis):
        """Successful skopeo should return digest and store mapping."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="sha256:abc123def456\n",
            stderr=""
        )

        cache = DigestCache()
        digest = cache.get_image_digest("nginx:latest")

        assert digest == "abc123def456"
        # Verify the digest mapping was stored
        stored = mock_redis.get("digest_map:nginx:latest")
        assert stored == "abc123def456"

    @patch("app.enrichment.subprocess.run")
    def test_skopeo_failure_returns_none(self, mock_run, mock_redis):
        """Failed skopeo should return None (force fresh scan)."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="connection refused"
        )

        cache = DigestCache()
        digest = cache.get_image_digest("nginx:latest")
        assert digest is None

    @patch("app.enrichment.subprocess.run")
    def test_skopeo_not_found(self, mock_run, mock_redis):
        """Missing skopeo binary should return None."""
        mock_run.side_effect = FileNotFoundError("skopeo not found")

        cache = DigestCache()
        digest = cache.get_image_digest("nginx:latest")
        assert digest is None

    @patch("app.enrichment.subprocess.run")
    def test_skopeo_timeout(self, mock_run, mock_redis):
        """Skopeo timeout should return None."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("skopeo", 60)

        cache = DigestCache()
        digest = cache.get_image_digest("nginx:latest")
        assert digest is None

    @patch("app.enrichment.subprocess.run")
    def test_digest_change_invalidates_old_cache(self, mock_run, mock_redis):
        """When digest changes, old cached scan should be invalidated."""
        # Seed old digest mapping and old cached scan
        mock_redis.set("digest_map:nginx:latest", "old_digest_111")
        mock_redis.set("digest_cache:old_digest_111", json.dumps({"scan_id": "old-scan"}))

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="sha256:new_digest_222\n",
            stderr=""
        )

        cache = DigestCache()
        digest = cache.get_image_digest("nginx:latest")

        assert digest == "new_digest_222"
        # Old cache should be invalidated
        assert mock_redis.get("digest_cache:old_digest_111") is None

    def test_cache_scan_result(self, mock_redis):
        """Caching a scan should store JSON with TTL."""
        cache = DigestCache()
        cache.cache_scan_result(
            digest="abc123",
            scan_id="scan-001",
            image_name="nginx:latest",
            result_summary={"total": 5}
        )

        cached = json.loads(mock_redis.get("digest_cache:abc123"))
        assert cached["scan_id"] == "scan-001"
        assert cached["image_name"] == "nginx:latest"
        assert cached["summary"]["total"] == 5

    def test_cache_scan_empty_digest(self, mock_redis):
        """Empty digest should not cache anything."""
        cache = DigestCache()
        cache.cache_scan_result("", "scan-001", "nginx", {})
        # Should not raise or store anything

    def test_get_cached_scan_hit(self, mock_redis):
        """Cached scan should be returned on cache hit."""
        data = {"scan_id": "scan-001", "digest": "abc123"}
        mock_redis.set("digest_cache:abc123", json.dumps(data))

        cache = DigestCache()
        result = cache.get_cached_scan("abc123")

        assert result is not None
        assert result["scan_id"] == "scan-001"

    def test_get_cached_scan_miss(self, mock_redis):
        """Cache miss should return None."""
        cache = DigestCache()
        result = cache.get_cached_scan("nonexistent_digest")
        assert result is None

    def test_get_cached_scan_empty_digest(self, mock_redis):
        """Empty digest should return None."""
        cache = DigestCache()
        assert cache.get_cached_scan("") is None
        assert cache.get_cached_scan(None) is None

    def test_invalidate_cache(self, mock_redis):
        """Invalidating should remove the cached entry."""
        mock_redis.set("digest_cache:abc123", json.dumps({"scan_id": "old"}))

        cache = DigestCache()
        result = cache.invalidate_cache("abc123")

        assert result is True
        assert mock_redis.get("digest_cache:abc123") is None

    def test_invalidate_nonexistent(self, mock_redis):
        """Invalidating a non-existent key should return False."""
        cache = DigestCache()
        assert cache.invalidate_cache("nonexistent") is False

    def test_invalidate_empty_digest(self, mock_redis):
        """Invalidating empty digest should return False."""
        cache = DigestCache()
        assert cache.invalidate_cache("") is False

    def test_cache_stats(self, mock_redis):
        """Cache stats should count cached digests."""
        mock_redis.set("digest_cache:aaa", "1")
        mock_redis.set("digest_cache:bbb", "2")

        cache = DigestCache()
        stats = cache.get_cache_stats()

        assert stats["cached_digests"] == 2
        assert stats["default_ttl_hours"] == 24


class TestVulnerabilityEnricher:
    """Tests for the main enrichment service."""

    def test_enrich_empty_list(self, mock_redis):
        """Empty vulnerability list should return empty results."""
        enricher = VulnerabilityEnricher()
        enriched, summary = enricher.enrich_vulnerabilities([])

        assert enriched == []
        assert summary["total"] == 0

    def test_risk_priority_kev(self, mock_redis):
        """KEV vulnerabilities should always be critical priority."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "Low", "in_kev": True, "epss_score": 0.01}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "critical"

    def test_risk_priority_high_epss(self, mock_redis):
        """EPSS >= 0.7 should be critical priority."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "Medium", "in_kev": False, "epss_score": 0.75}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "critical"

    def test_risk_priority_medium_epss(self, mock_redis):
        """EPSS >= 0.4 should be high priority."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "Low", "in_kev": False, "epss_score": 0.5}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "high"

    def test_risk_priority_critical_with_epss(self, mock_redis):
        """Critical severity with EPSS >= 0.1 should be critical."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "critical", "in_kev": False, "epss_score": 0.15}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "critical"

    def test_risk_priority_critical_low_epss(self, mock_redis):
        """Critical severity with EPSS < 0.1 should be high."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "critical", "in_kev": False, "epss_score": 0.05}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "high"

    def test_risk_priority_high_severity(self, mock_redis):
        """High severity with EPSS >= 0.1 should be high priority."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "high", "in_kev": False, "epss_score": 0.15}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "high"

    def test_risk_priority_medium_severity(self, mock_redis):
        """Medium severity should be medium priority."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "medium", "in_kev": False, "epss_score": 0.01}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "medium"

    def test_risk_priority_low_severity(self, mock_redis):
        """Low severity should be low priority."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "low", "in_kev": False, "epss_score": 0}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "low"

    def test_risk_priority_unknown(self, mock_redis):
        """Unknown severity should be info priority."""
        enricher = VulnerabilityEnricher()

        vuln = {"severity": "negligible", "in_kev": False, "epss_score": 0}
        priority = enricher._calculate_risk_priority(vuln)
        assert priority == "info"


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    @patch("app.enrichment.subprocess.run")
    def test_check_digest_cache_no_digest(self, mock_run, mock_redis):
        """No digest resolved should return (None, None)."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")

        digest, cached = check_digest_cache("nginx:latest")
        assert digest is None
        assert cached is None

    @patch("app.enrichment.subprocess.run")
    def test_check_digest_cache_no_cached_scan(self, mock_run, mock_redis):
        """Digest resolved but no cached scan should return (digest, None)."""
        mock_run.return_value = MagicMock(returncode=0, stdout="sha256:abc123\n", stderr="")

        digest, cached = check_digest_cache("nginx:latest")
        assert digest == "abc123"
        assert cached is None

    @patch("app.enrichment.subprocess.run")
    def test_check_digest_cache_hit(self, mock_run, mock_redis):
        """Digest with cached scan should return both."""
        mock_run.return_value = MagicMock(returncode=0, stdout="sha256:abc123\n", stderr="")
        mock_redis.set("digest_cache:abc123", json.dumps({"scan_id": "scan-001"}))

        digest, cached = check_digest_cache("nginx:latest")
        assert digest == "abc123"
        assert cached is not None
        assert cached["scan_id"] == "scan-001"

    def test_cache_scan_by_digest(self, mock_redis):
        """Convenience function should cache the scan result."""
        cache_scan_by_digest("abc123", "scan-001", "nginx:latest", {"total": 5})

        cached = json.loads(mock_redis.get("digest_cache:abc123"))
        assert cached["scan_id"] == "scan-001"
