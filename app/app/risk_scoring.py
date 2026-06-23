"""
Advanced Risk Scoring Model
Custom weighted scoring based on exploitability, network exposure, and other factors
"""
import json
import httpx
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict

from app.config import settings, get_redis_client
from app.time_utils import now_iso
from app.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class RiskFactors:
    """Individual risk factors for a vulnerability"""
    base_cvss_score: float = 0.0
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    is_network_exploitable: bool = False
    has_known_exploit: bool = False
    is_actively_exploited: bool = False
    has_public_poc: bool = False
    fix_available: bool = False
    age_days: int = 0
    affected_component_type: str = "unknown"
    is_in_base_image: bool = False


@dataclass
class RiskScore:
    """Comprehensive risk score for a vulnerability"""
    vuln_id: str
    raw_score: float
    weighted_score: float
    risk_level: str  # "critical", "high", "medium", "low", "info"
    factors: RiskFactors
    recommendations: List[str]


class RiskScoringEngine:
    """
    Advanced risk scoring engine that considers multiple factors
    beyond just CVSS scores
    """

    # Default weights for risk factors (can be customized)
    DEFAULT_WEIGHTS = {
        "base_cvss": 0.25,           # Base CVSS score weight
        "exploitability": 0.20,      # Exploitability metrics
        "network_exposure": 0.15,    # Network-accessible vulnerabilities
        "known_exploit": 0.15,       # Known exploits in the wild
        "active_exploitation": 0.10, # Currently being exploited (KEV)
        "fix_availability": 0.05,    # Is a fix available?
        "age": 0.05,                 # How old is the vulnerability?
        "component_criticality": 0.05  # How critical is the component?
    }

    # CISA KEV API endpoint
    KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Exploit-DB patterns (simplified check)
    EXPLOIT_KEYWORDS = ["exploit", "poc", "proof of concept", "metasploit"]

    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        self.redis = get_redis_client()
        self.weights = custom_weights or self.DEFAULT_WEIGHTS
        self._kev_cache = None
        self._kev_cache_time = None

    def calculate_risk_score(
        self,
        vulnerability: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for a vulnerability

        Args:
            vulnerability: Vulnerability data from scan
            context: Additional context (component type, is_base_image, etc.)

        Returns:
            Risk score with breakdown
        """
        context = context or {}

        # Extract risk factors
        factors = self._extract_risk_factors(vulnerability, context)

        # Calculate weighted score
        weighted_score = self._calculate_weighted_score(factors)

        # Determine risk level
        risk_level = self._determine_risk_level(weighted_score, factors)

        # Generate recommendations
        recommendations = self._generate_recommendations(factors, risk_level)

        return {
            "vuln_id": vulnerability.get("id", "unknown"),
            "package": vulnerability.get("package_name") or vulnerability.get("package", "unknown"),
            "version": vulnerability.get("package_version") or vulnerability.get("version", "unknown"),
            "raw_cvss_score": factors.base_cvss_score,
            "weighted_score": round(weighted_score, 2),
            "risk_level": risk_level,
            "factors": asdict(factors),
            "factor_breakdown": self._get_factor_breakdown(factors),
            "recommendations": recommendations
        }

    def _extract_risk_factors(
        self,
        vulnerability: Dict[str, Any],
        context: Dict[str, Any]
    ) -> RiskFactors:
        """Extract all risk factors from vulnerability data"""
        factors = RiskFactors()

        # Base CVSS score - check multiple possible field names
        # First check cvss_score as top-level field (Grype/Trivy format)
        cvss_score = vulnerability.get("cvss_score")
        if cvss_score:
            try:
                factors.base_cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                factors.base_cvss_score = 0
        else:
            # Fall back to cvss dict format
            cvss = vulnerability.get("cvss", {})
            if isinstance(cvss, dict) and cvss:
                factors.base_cvss_score = cvss.get("score", 0) or cvss.get("base_score", 0) or 0
            elif cvss:
                try:
                    factors.base_cvss_score = float(cvss)
                except (ValueError, TypeError):
                    factors.base_cvss_score = 0
            else:
                factors.base_cvss_score = 0

        # Exploitability and impact from CVSS metrics
        cvss_metrics = vulnerability.get("cvss_metrics", {})
        factors.exploitability_score = cvss_metrics.get("exploitabilityScore", 0)
        factors.impact_score = cvss_metrics.get("impactScore", 0)

        # Network exploitability (check attack vector)
        attack_vector = cvss_metrics.get("attackVector", "").upper()
        factors.is_network_exploitable = attack_vector in ["NETWORK", "ADJACENT_NETWORK", "N", "A"]

        # Check for known exploits
        vuln_id = vulnerability.get("id", "")
        factors.has_known_exploit = self._check_known_exploit(vuln_id)
        factors.is_actively_exploited = self._check_kev(vuln_id)

        # Fix availability - check multiple possible field names
        if "fix_available" in vulnerability:
            factors.fix_available = bool(vulnerability.get("fix_available"))
        else:
            fix_version = vulnerability.get("fix_version") or vulnerability.get("fixed_in") or vulnerability.get("fix_versions")
            if isinstance(fix_version, list):
                factors.fix_available = len(fix_version) > 0
            else:
                factors.fix_available = bool(fix_version and fix_version != "unknown" and fix_version != "")

        # Vulnerability age
        published_date = vulnerability.get("published_date")
        if published_date:
            try:
                pub_dt = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
                factors.age_days = (datetime.now(pub_dt.tzinfo) - pub_dt).days
            except Exception:
                factors.age_days = 0

        # Context factors
        factors.affected_component_type = context.get("component_type", "unknown")
        factors.is_in_base_image = context.get("is_base_image", False)

        return factors

    def _check_known_exploit(self, vuln_id: str) -> bool:
        """Check if vulnerability has known exploits"""
        # Check cache first
        cache_key = f"exploit_check:{vuln_id}"
        cached = self.redis.get(cache_key)
        if cached is not None:
            return cached == "1"

        # Simple heuristic check (in production, would query exploit-db API)
        has_exploit = False

        # Cache result for 24 hours
        self.redis.setex(cache_key, 86400, "1" if has_exploit else "0")

        return has_exploit

    def _check_kev(self, vuln_id: str) -> bool:
        """Check if vulnerability is in CISA KEV (Known Exploited Vulnerabilities)"""
        try:
            kev_list = self._get_kev_list()
            return vuln_id.upper() in kev_list
        except Exception as e:
            logger.warning(f"KEV check failed: {e}")
            return False

    def _get_kev_list(self) -> set:
        """Get CISA KEV list (cached)"""
        # Check memory cache (valid for 1 hour)
        if self._kev_cache and self._kev_cache_time:
            if datetime.now() - self._kev_cache_time < timedelta(hours=1):
                return self._kev_cache

        # Check Redis cache
        cache_key = "cisa_kev_list"
        cached = self.redis.get(cache_key)
        if cached:
            self._kev_cache = set(json.loads(cached))
            self._kev_cache_time = datetime.now()
            return self._kev_cache

        # Fetch from CISA
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(self.KEV_API_URL)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    kev_set = {v.get("cveID", "").upper() for v in vulnerabilities}

                    # Cache for 6 hours
                    self.redis.setex(cache_key, 21600, json.dumps(list(kev_set)))
                    self._kev_cache = kev_set
                    self._kev_cache_time = datetime.now()
                    return kev_set
        except Exception as e:
            logger.warning(f"Failed to fetch KEV list: {e}")

        return set()

    def _calculate_weighted_score(self, factors: RiskFactors) -> float:
        """Calculate the weighted risk score"""
        score = 0.0

        # Base CVSS contribution (normalized to 0-10)
        score += factors.base_cvss_score * self.weights["base_cvss"]

        # Exploitability contribution
        exploit_score = factors.exploitability_score / 10 * 10  # Normalize
        score += exploit_score * self.weights["exploitability"]

        # Network exposure
        if factors.is_network_exploitable:
            score += 10 * self.weights["network_exposure"]

        # Known exploit
        if factors.has_known_exploit:
            score += 10 * self.weights["known_exploit"]

        # Active exploitation (highest risk)
        if factors.is_actively_exploited:
            score += 10 * self.weights["active_exploitation"]

        # Fix availability (reduces risk if fix exists)
        if not factors.fix_available:
            score += 5 * self.weights["fix_availability"]

        # Age factor (older unfixed vulns are higher risk)
        if factors.age_days > 365 and not factors.fix_available:
            score += 5 * self.weights["age"]
        elif factors.age_days > 90 and not factors.fix_available:
            score += 3 * self.weights["age"]

        # Component criticality
        critical_types = ["kernel", "openssl", "glibc", "openssh", "sudo"]
        if any(ct in factors.affected_component_type.lower() for ct in critical_types):
            score += 5 * self.weights["component_criticality"]

        # Ensure score is within bounds
        return min(10.0, max(0.0, score))

    def _determine_risk_level(self, score: float, factors: RiskFactors) -> str:
        """Determine risk level from score and factors"""
        # Override to critical if actively exploited
        if factors.is_actively_exploited:
            return "critical"

        # Override to high if network exploitable with known exploit
        if factors.is_network_exploitable and factors.has_known_exploit:
            return "high" if score < 9 else "critical"

        # Score-based classification
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 0.1:
            return "low"
        else:
            return "info"

    def _get_factor_breakdown(self, factors: RiskFactors) -> Dict[str, Any]:
        """Get detailed breakdown of how factors contributed to score"""
        breakdown = []

        breakdown.append({
            "factor": "Base CVSS Score",
            "value": factors.base_cvss_score,
            "weight": self.weights["base_cvss"],
            "contribution": round(factors.base_cvss_score * self.weights["base_cvss"], 2)
        })

        if factors.is_network_exploitable:
            breakdown.append({
                "factor": "Network Exploitable",
                "value": "Yes",
                "weight": self.weights["network_exposure"],
                "contribution": round(10 * self.weights["network_exposure"], 2)
            })

        if factors.has_known_exploit:
            breakdown.append({
                "factor": "Known Exploit",
                "value": "Yes",
                "weight": self.weights["known_exploit"],
                "contribution": round(10 * self.weights["known_exploit"], 2)
            })

        if factors.is_actively_exploited:
            breakdown.append({
                "factor": "Actively Exploited (KEV)",
                "value": "Yes",
                "weight": self.weights["active_exploitation"],
                "contribution": round(10 * self.weights["active_exploitation"], 2)
            })

        breakdown.append({
            "factor": "Fix Available",
            "value": "Yes" if factors.fix_available else "No",
            "weight": self.weights["fix_availability"],
            "impact": "Reduces risk" if factors.fix_available else "Increases risk"
        })

        return breakdown

    def _generate_recommendations(
        self,
        factors: RiskFactors,
        risk_level: str
    ) -> List[str]:
        """Generate actionable recommendations based on risk factors"""
        recommendations = []

        if factors.is_actively_exploited:
            recommendations.append(
                "URGENT: This vulnerability is being actively exploited in the wild. "
                "Prioritize immediate patching or implement compensating controls."
            )

        if factors.is_network_exploitable and not factors.fix_available:
            recommendations.append(
                "Consider network segmentation or WAF rules to limit exposure "
                "until a fix is available."
            )

        if factors.fix_available:
            recommendations.append(
                "A fix is available. Schedule upgrade during next maintenance window."
            )
        else:
            recommendations.append(
                "No fix available. Consider alternative packages or implement "
                "compensating controls."
            )

        if factors.has_known_exploit and factors.is_network_exploitable:
            recommendations.append(
                "Enable enhanced monitoring and logging for this component."
            )

        if risk_level == "critical":
            recommendations.append(
                "Create incident ticket and assign to security team for immediate action."
            )
        elif risk_level == "high":
            recommendations.append(
                "Address within current sprint or maintenance cycle."
            )

        return recommendations

    def calculate_image_risk_score(self, scan_id: str) -> Dict[str, Any]:
        """
        Calculate overall risk score for an entire image scan

        Args:
            scan_id: The scan ID to calculate risk for

        Returns:
            Comprehensive risk assessment for the image
        """
        # Check cache first (cache for 1 hour)
        cache_key = f"risk_score:{scan_id}"
        cached = self.redis.get(cache_key)
        if cached:
            return json.loads(cached)

        # Get vulnerability data
        vulns_key = f"vulns:{scan_id}"
        vulns_data = self.redis.get(vulns_key)

        if not vulns_data:
            return {"error": "Scan results not found"}

        vulnerabilities = json.loads(vulns_data)

        # Per-vulnerability weighted scores — kept only for the top_risks list
        # below (supplementary detail), NOT for the headline image score.
        vuln_scores = [self.calculate_risk_score(v) for v in vulnerabilities]

        # Severity distribution comes from the SCANNER-assigned severity — the
        # authoritative, always-populated signal. (The per-vuln weighted level
        # collapses everything to "low" when CVSS metrics are absent, which is
        # why the old aggregate ignored criticals entirely.)
        risk_distribution = defaultdict(int)
        high_epss = 0
        kev_count = 0
        for vuln in vulnerabilities:
            sev = (vuln.get("severity") or "unknown").strip().lower()
            risk_distribution[sev] += 1
            try:
                if float(vuln.get("epss_score") or 0) >= 0.5:
                    high_epss += 1
            except (ValueError, TypeError):
                pass
            if vuln.get("in_kev") or vuln.get("kev_match"):
                kev_count += 1

        # Supplementary per-vuln metrics (shown as detail, not the headline).
        if vuln_scores:
            max_score = max(vs["weighted_score"] for vs in vuln_scores)
            avg_score = sum(vs["weighted_score"] for vs in vuln_scores) / len(vuln_scores)
        else:
            max_score = 0
            avg_score = 0
        actively_exploited = kev_count

        # Headline image risk — severity-driven and saturating: the worst
        # findings dominate, more low/medium findings can never lower it, KEV
        # forces a critical floor, high-EPSS adds an exploit-likelihood boost.
        overall_score = self._calculate_image_aggregate_score(
            risk_distribution, high_epss, kev_count
        )
        overall_level = self._determine_risk_level(
            overall_score,
            RiskFactors(is_actively_exploited=kev_count > 0)
        )

        # Get top risks
        top_risks = sorted(
            vuln_scores,
            key=lambda x: x["weighted_score"],
            reverse=True
        )[:10]

        result = {
            "scan_id": scan_id,
            "calculated_at": now_iso(),
            "overall_risk_score": round(overall_score, 2),
            "overall_risk_level": overall_level,
            "max_vulnerability_score": round(max_score, 2),
            "average_vulnerability_score": round(avg_score, 2),
            "total_vulnerabilities": len(vulnerabilities),
            "actively_exploited_count": actively_exploited,
            "risk_distribution": dict(risk_distribution),
            "top_risks": top_risks,
            "recommendations": self._generate_image_recommendations(
                overall_level, risk_distribution, actively_exploited
            )
        }

        # Cache result for 1 hour
        self.redis.setex(cache_key, 3600, json.dumps(result))

        return result

    def _calculate_image_aggregate_score(
        self,
        severity_distribution: Dict[str, int],
        high_epss_count: int = 0,
        kev_count: int = 0,
    ) -> float:
        """Aggregate an image's risk (0-10) from its scanner-severity counts.

        Severity-driven and SATURATING: the worst findings dominate, and adding
        more low/medium findings can never reduce the score (no averaging /
        dilution). KEV (actively exploited) forces a critical floor; a high-EPSS
        population adds an exploit-likelihood boost.
        """
        crit = severity_distribution.get("critical", 0)
        high = severity_distribution.get("high", 0)
        med = severity_distribution.get("medium", 0)
        low = severity_distribution.get("low", 0)

        # The highest severity PRESENT sets the band (floor); the count within
        # that band scales the score upward. This keeps the level intuitive:
        # any critical -> critical band, many highs -> high band, etc., and is
        # monotonic (adding a worse finding can only raise the score).
        if crit > 0:
            score = 7.0 + min(3.0, crit * 0.5)     # 1 crit -> 7.5, 6+ -> 10 (critical)
        elif high > 0:
            score = 5.0 + min(2.5, high * 0.3)     # ~7+ highs -> high band
        elif med > 0:
            score = 2.5 + min(1.4, med * 0.06)     # mostly-medium -> low/medium
        elif low > 0:
            score = 1.0 + min(0.9, low * 0.04)
        else:
            score = 0.0

        # Exploit-likelihood boost, then KEV (actively exploited) critical floor.
        score += min(1.0, high_epss_count * 0.5)
        if kev_count > 0:
            score = max(score, 9.0)
        return min(10.0, score)

    def _generate_image_recommendations(
        self,
        risk_level: str,
        distribution: Dict[str, int],
        actively_exploited: int
    ) -> List[str]:
        """Generate recommendations for the overall image"""
        recommendations = []

        if actively_exploited > 0:
            recommendations.append(
                f"CRITICAL: {actively_exploited} vulnerabilities are actively exploited. "
                "Immediate action required."
            )

        critical = distribution.get("critical", 0)
        high = distribution.get("high", 0)

        if critical > 0:
            recommendations.append(
                f"Address {critical} critical vulnerabilities before deployment."
            )

        if high > 5:
            recommendations.append(
                f"High number of high-severity vulnerabilities ({high}). "
                "Consider image rebuild with updated base."
            )

        if risk_level in ["critical", "high"]:
            recommendations.append(
                "This image should not be deployed to production in current state."
            )
        elif risk_level == "medium":
            recommendations.append(
                "Address vulnerabilities during next maintenance window."
            )
        else:
            recommendations.append(
                "Image risk level acceptable. Continue regular scanning."
            )

        return recommendations

    def update_weights(self, new_weights: Dict[str, float]) -> Dict[str, float]:
        """
        Update risk scoring weights

        Args:
            new_weights: Dictionary of factor weights (must sum to 1.0)

        Returns:
            Updated weights
        """
        total = sum(new_weights.values())
        if abs(total - 1.0) > 0.01:
            # Normalize weights
            new_weights = {k: v / total for k, v in new_weights.items()}

        self.weights.update(new_weights)

        # Cache updated weights
        self.redis.set("risk_weights", json.dumps(self.weights))

        return self.weights

    def get_weights(self) -> Dict[str, float]:
        """Get current risk scoring weights"""
        cached = self.redis.get("risk_weights")
        if cached:
            return json.loads(cached)
        return self.weights
