"""
Vulnerability Enrichment Module
- EPSS (Exploit Prediction Scoring System) integration
- CISA KEV (Known Exploited Vulnerabilities) integration
- Image digest-based scan caching
"""
import json
import httpx
import hashlib
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import redis

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

# Redis connection
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=10,
    decode_responses=True
)


def get_redis_client() -> redis.Redis:
    return redis.Redis(connection_pool=redis_pool)


# =============================================================================
# EPSS (Exploit Prediction Scoring System) Integration
# =============================================================================

class EPSSClient:
    """Client for FIRST EPSS API"""

    BASE_URL = "https://api.first.org/data/v1/epss"
    CACHE_TTL = 86400  # 24 hours
    CACHE_KEY_PREFIX = "epss:"

    def __init__(self):
        self.redis = get_redis_client()

    def get_epss_scores(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Get EPSS scores for a list of CVE IDs.
        Returns dict mapping CVE ID to {epss, percentile, date}
        """
        if not cve_ids:
            return {}

        # Normalize CVE IDs
        cve_ids = [cve.upper() for cve in cve_ids if cve and cve.upper().startswith("CVE-")]

        if not cve_ids:
            return {}

        results = {}
        uncached_cves = []

        # Check cache first using pipeline
        pipe = self.redis.pipeline()
        for cve_id in cve_ids:
            pipe.get(f"{self.CACHE_KEY_PREFIX}{cve_id}")
        cached_results = pipe.execute()

        for cve_id, cached in zip(cve_ids, cached_results):
            if cached:
                results[cve_id] = json.loads(cached)
            else:
                uncached_cves.append(cve_id)

        # Fetch uncached CVEs from API (batch in groups of 100)
        if uncached_cves:
            for i in range(0, len(uncached_cves), 100):
                batch = uncached_cves[i:i + 100]
                batch_results = self._fetch_epss_batch(batch)
                results.update(batch_results)

                # Cache the results
                pipe = self.redis.pipeline()
                for cve_id, data in batch_results.items():
                    pipe.setex(
                        f"{self.CACHE_KEY_PREFIX}{cve_id}",
                        self.CACHE_TTL,
                        json.dumps(data)
                    )
                pipe.execute()

        return results

    def _fetch_epss_batch(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Fetch EPSS scores for a batch of CVEs"""
        results = {}

        try:
            # EPSS API accepts comma-separated CVE IDs
            params = {"cve": ",".join(cve_ids)}

            with httpx.Client(timeout=30.0) as client:
                response = client.get(self.BASE_URL, params=params)
                response.raise_for_status()
                data = response.json()

            for item in data.get("data", []):
                cve_id = item.get("cve", "").upper()
                if cve_id:
                    results[cve_id] = {
                        "epss_score": float(item.get("epss", 0)),
                        "epss_percentile": float(item.get("percentile", 0)),
                        "epss_date": item.get("date")
                    }

            logger.info(
                "Fetched EPSS scores",
                requested=len(cve_ids),
                found=len(results)
            )

        except httpx.HTTPError as e:
            logger.warning(f"EPSS API error: {e}")
        except Exception as e:
            logger.error(f"EPSS fetch error: {e}")

        return results

    def get_single_score(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get EPSS score for a single CVE"""
        scores = self.get_epss_scores([cve_id])
        return scores.get(cve_id.upper())


# =============================================================================
# CISA KEV (Known Exploited Vulnerabilities) Integration
# =============================================================================

class KEVClient:
    """Client for CISA Known Exploited Vulnerabilities catalog"""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_KEY = "kev:catalog"
    CACHE_TTL = 43200  # 12 hours
    CVE_SET_KEY = "kev:cve_set"
    LAST_UPDATE_KEY = "kev:last_update"

    def __init__(self):
        self.redis = get_redis_client()

    def update_kev_database(self) -> Dict[str, Any]:
        """Fetch and cache the KEV catalog"""
        try:
            with httpx.Client(timeout=60.0) as client:
                response = client.get(self.KEV_URL)
                response.raise_for_status()
                data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            catalog_version = data.get("catalogVersion", "unknown")

            # Store the full catalog
            self.redis.setex(self.CACHE_KEY, self.CACHE_TTL, json.dumps(data))

            # Build a set of CVE IDs for fast lookup
            cve_ids = [v.get("cveID", "").upper() for v in vulnerabilities if v.get("cveID")]

            # Use pipeline to update the set
            pipe = self.redis.pipeline()
            pipe.delete(self.CVE_SET_KEY)
            if cve_ids:
                pipe.sadd(self.CVE_SET_KEY, *cve_ids)
            pipe.set(self.LAST_UPDATE_KEY, datetime.now().isoformat())
            pipe.execute()

            logger.info(
                "KEV database updated",
                total_cves=len(cve_ids),
                catalog_version=catalog_version
            )

            return {
                "status": "updated",
                "total_cves": len(cve_ids),
                "catalog_version": catalog_version,
                "updated_at": datetime.now().isoformat()
            }

        except httpx.HTTPError as e:
            logger.error(f"KEV fetch error: {e}")
            return {"status": "error", "error": str(e)}
        except Exception as e:
            logger.error(f"KEV update error: {e}")
            return {"status": "error", "error": str(e)}

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog"""
        if not cve_id:
            return False
        return self.redis.sismember(self.CVE_SET_KEY, cve_id.upper())

    def check_cves(self, cve_ids: List[str]) -> Dict[str, bool]:
        """Check multiple CVEs against KEV catalog"""
        if not cve_ids:
            return {}

        # Ensure KEV data exists
        if not self.redis.exists(self.CVE_SET_KEY):
            self.update_kev_database()

        results = {}
        pipe = self.redis.pipeline()
        normalized_cves = [cve.upper() for cve in cve_ids if cve]

        for cve_id in normalized_cves:
            pipe.sismember(self.CVE_SET_KEY, cve_id)

        kev_results = pipe.execute()

        for cve_id, is_kev in zip(normalized_cves, kev_results):
            results[cve_id] = bool(is_kev)

        return results

    def get_kev_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get full KEV details for a CVE"""
        if not self.is_in_kev(cve_id):
            return None

        cached = self.redis.get(self.CACHE_KEY)
        if not cached:
            self.update_kev_database()
            cached = self.redis.get(self.CACHE_KEY)

        if cached:
            data = json.loads(cached)
            for vuln in data.get("vulnerabilities", []):
                if vuln.get("cveID", "").upper() == cve_id.upper():
                    return {
                        "cve_id": vuln.get("cveID"),
                        "vendor": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "date_added": vuln.get("dateAdded"),
                        "short_description": vuln.get("shortDescription"),
                        "required_action": vuln.get("requiredAction"),
                        "due_date": vuln.get("dueDate"),
                        "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown")
                    }

        return None

    def get_kev_stats(self) -> Dict[str, Any]:
        """Get KEV catalog statistics"""
        total = self.redis.scard(self.CVE_SET_KEY)
        last_update = self.redis.get(self.LAST_UPDATE_KEY)

        return {
            "total_kev_cves": total,
            "last_update": last_update,
            "cache_ttl_hours": self.CACHE_TTL // 3600
        }


# =============================================================================
# Image Digest Cache
# =============================================================================

class DigestCache:
    """Cache scan results by image digest to avoid redundant scans"""

    CACHE_KEY_PREFIX = "digest_cache:"
    DIGEST_MAP_PREFIX = "digest_map:"  # Maps image:tag to digest
    DEFAULT_TTL = 86400  # 24 hours

    def __init__(self):
        self.redis = get_redis_client()

    def get_image_digest(self, image_name: str) -> Optional[str]:
        """
        Get the digest of a Docker image.
        Uses 'docker inspect' or 'skopeo inspect' for remote images.
        """
        try:
            # First check if we have a cached digest mapping
            cached_digest = self.redis.get(f"{self.DIGEST_MAP_PREFIX}{image_name}")
            if cached_digest:
                return cached_digest

            # Try docker inspect first (works for pulled images)
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                digest_full = result.stdout.strip()
                # Extract just the sha256 part
                if "@sha256:" in digest_full:
                    digest = digest_full.split("@sha256:")[-1]
                    # Cache the mapping
                    self.redis.setex(f"{self.DIGEST_MAP_PREFIX}{image_name}", 3600, digest)
                    return digest

            # Try skopeo for remote images
            result = subprocess.run(
                ["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{image_name}"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0 and result.stdout.strip():
                digest = result.stdout.strip().replace("sha256:", "")
                self.redis.setex(f"{self.DIGEST_MAP_PREFIX}{image_name}", 3600, digest)
                return digest

            # Fallback: create a hash of image name + current date (less optimal)
            # This ensures daily rescans at minimum
            date_str = datetime.now().strftime("%Y-%m-%d")
            fallback_digest = hashlib.sha256(f"{image_name}:{date_str}".encode()).hexdigest()
            logger.warning(f"Could not get digest for {image_name}, using fallback hash")
            return fallback_digest

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout getting digest for {image_name}")
            return None
        except Exception as e:
            logger.error(f"Error getting digest for {image_name}: {e}")
            return None

    def get_cached_scan(self, digest: str) -> Optional[Dict[str, Any]]:
        """Get cached scan result by digest"""
        if not digest:
            return None

        cached = self.redis.get(f"{self.CACHE_KEY_PREFIX}{digest}")
        if cached:
            data = json.loads(cached)
            logger.info(f"Cache hit for digest {digest[:12]}...")
            return data

        return None

    def cache_scan_result(
        self,
        digest: str,
        scan_id: str,
        image_name: str,
        result_summary: Dict[str, Any],
        ttl: int = None
    ) -> None:
        """Cache a scan result by digest"""
        if not digest:
            return

        cache_data = {
            "scan_id": scan_id,
            "image_name": image_name,
            "digest": digest,
            "cached_at": datetime.now().isoformat(),
            "summary": result_summary
        }

        self.redis.setex(
            f"{self.CACHE_KEY_PREFIX}{digest}",
            ttl or self.DEFAULT_TTL,
            json.dumps(cache_data)
        )

        logger.info(f"Cached scan result for digest {digest[:12]}...")

    def invalidate_cache(self, digest: str) -> bool:
        """Invalidate a cached scan result"""
        if not digest:
            return False
        return bool(self.redis.delete(f"{self.CACHE_KEY_PREFIX}{digest}"))

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        # Count cached digests using SCAN
        cursor = 0
        count = 0
        while True:
            cursor, keys = self.redis.scan(cursor, match=f"{self.CACHE_KEY_PREFIX}*", count=100)
            count += len(keys)
            if cursor == 0:
                break

        return {
            "cached_digests": count,
            "default_ttl_hours": self.DEFAULT_TTL // 3600
        }


# =============================================================================
# Vulnerability Enrichment Service
# =============================================================================

class VulnerabilityEnricher:
    """
    Enriches vulnerability data with EPSS scores and KEV status.
    """

    def __init__(self):
        self.epss_client = EPSSClient()
        self.kev_client = KEVClient()
        self.redis = get_redis_client()

    def enrich_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        scan_id: str = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Enrich a list of vulnerabilities with EPSS and KEV data.
        Returns (enriched_vulnerabilities, enrichment_summary)
        """
        if not vulnerabilities:
            return [], {"total": 0, "epss_enriched": 0, "kev_matches": 0}

        # Extract unique CVE IDs
        cve_ids = list(set(
            v.get("id", "") for v in vulnerabilities
            if v.get("id", "").upper().startswith("CVE-")
        ))

        # Fetch EPSS scores and KEV status in parallel
        epss_scores = self.epss_client.get_epss_scores(cve_ids) if cve_ids else {}
        kev_status = self.kev_client.check_cves(cve_ids) if cve_ids else {}

        # Enrich each vulnerability
        enriched = []
        epss_enriched = 0
        kev_matches = 0
        high_risk_count = 0

        for vuln in vulnerabilities:
            enriched_vuln = vuln.copy()
            cve_id = vuln.get("id", "").upper()

            # Add EPSS data
            if cve_id in epss_scores:
                epss_data = epss_scores[cve_id]
                enriched_vuln["epss_score"] = epss_data.get("epss_score", 0)
                enriched_vuln["epss_percentile"] = epss_data.get("epss_percentile", 0)
                epss_enriched += 1
            else:
                enriched_vuln["epss_score"] = None
                enriched_vuln["epss_percentile"] = None

            # Add KEV status
            enriched_vuln["in_kev"] = kev_status.get(cve_id, False)
            if enriched_vuln["in_kev"]:
                kev_matches += 1

            # Calculate risk priority
            enriched_vuln["risk_priority"] = self._calculate_risk_priority(enriched_vuln)
            if enriched_vuln["risk_priority"] == "critical":
                high_risk_count += 1

            enriched.append(enriched_vuln)

        # Sort by risk priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        enriched.sort(key=lambda x: (
            priority_order.get(x.get("risk_priority", "info"), 99),
            -(x.get("epss_score") or 0)
        ))

        summary = {
            "total": len(vulnerabilities),
            "epss_enriched": epss_enriched,
            "kev_matches": kev_matches,
            "high_risk_vulns": high_risk_count,
            "enriched_at": datetime.now().isoformat()
        }

        # Cache enrichment summary if scan_id provided
        if scan_id:
            self.redis.setex(
                f"enrichment:{scan_id}",
                settings.SCAN_RESULT_TTL,
                json.dumps(summary)
            )

        logger.info(
            "Vulnerabilities enriched",
            total=len(vulnerabilities),
            epss_enriched=epss_enriched,
            kev_matches=kev_matches
        )

        return enriched, summary

    def _calculate_risk_priority(self, vuln: Dict[str, Any]) -> str:
        """
        Calculate risk priority based on:
        - KEV status (known exploited = critical)
        - EPSS score (>0.7 = critical, >0.4 = high)
        - Base severity
        - Fix availability
        """
        severity = vuln.get("severity", "").lower()
        epss_score = vuln.get("epss_score") or 0
        in_kev = vuln.get("in_kev", False)
        has_fix = vuln.get("fix_available", False)

        # KEV = always critical priority
        if in_kev:
            return "critical"

        # High EPSS score
        if epss_score >= 0.7:
            return "critical"
        if epss_score >= 0.4:
            return "high"

        # Base severity with EPSS adjustment
        if severity == "critical":
            return "critical" if epss_score >= 0.1 else "high"
        if severity == "high":
            return "high" if epss_score >= 0.1 else "medium"
        if severity == "medium":
            return "medium"
        if severity == "low":
            return "low"

        return "info"

    def get_enrichment_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get cached enrichment summary for a scan"""
        cached = self.redis.get(f"enrichment:{scan_id}")
        if cached:
            return json.loads(cached)
        return None


# =============================================================================
# Convenience Functions
# =============================================================================

def enrich_scan_results(
    vulnerabilities: List[Dict[str, Any]],
    scan_id: str = None
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Convenience function to enrich vulnerabilities"""
    enricher = VulnerabilityEnricher()
    return enricher.enrich_vulnerabilities(vulnerabilities, scan_id)


def check_digest_cache(image_name: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Check if we have a cached scan for this image.
    Returns (digest, cached_scan) or (digest, None) if no cache
    """
    cache = DigestCache()
    digest = cache.get_image_digest(image_name)

    if digest:
        cached = cache.get_cached_scan(digest)
        return digest, cached

    return None, None


def cache_scan_by_digest(
    digest: str,
    scan_id: str,
    image_name: str,
    summary: Dict[str, Any]
) -> None:
    """Cache a scan result by its digest"""
    cache = DigestCache()
    cache.cache_scan_result(digest, scan_id, image_name, summary)


def update_kev_database() -> Dict[str, Any]:
    """Update the KEV database"""
    client = KEVClient()
    return client.update_kev_database()


def get_kev_stats() -> Dict[str, Any]:
    """Get KEV database statistics"""
    client = KEVClient()
    return client.get_kev_stats()
