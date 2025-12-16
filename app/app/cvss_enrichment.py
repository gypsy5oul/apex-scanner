"""
CVSS Score Enrichment and Exploitability Metrics
Provides detailed CVSS v3.1 scoring with attack vector analysis
"""
import json
import httpx
import redis
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import asyncio
import re

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

# Redis for caching CVSS data
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=10,
    decode_responses=True
)


def get_redis_client() -> redis.Redis:
    return redis.Redis(connection_pool=redis_pool)


@dataclass
class CVSSv3Score:
    """CVSS v3.1 Score Details"""
    base_score: float
    severity: str
    vector_string: str

    # Base Metrics
    attack_vector: str  # Network, Adjacent, Local, Physical
    attack_complexity: str  # Low, High
    privileges_required: str  # None, Low, High
    user_interaction: str  # None, Required
    scope: str  # Unchanged, Changed

    # Impact Metrics
    confidentiality_impact: str  # None, Low, High
    integrity_impact: str  # None, Low, High
    availability_impact: str  # None, Low, High

    # Temporal Metrics (if available)
    exploit_code_maturity: Optional[str] = None
    remediation_level: Optional[str] = None
    report_confidence: Optional[str] = None

    # Exploitability
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None

    # Additional context
    is_exploited: bool = False
    has_public_exploit: bool = False
    epss_score: Optional[float] = None  # Exploit Prediction Scoring System
    epss_percentile: Optional[float] = None


class CVSSEnricher:
    """Enrich vulnerabilities with CVSS details"""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_TTL = 86400 * 7  # 7 days cache

    def __init__(self):
        self.redis = get_redis_client()

    def parse_cvss_vector(self, vector_string: str) -> Dict[str, str]:
        """Parse CVSS v3.x vector string into components"""
        if not vector_string:
            return {}

        components = {}
        # Remove CVSS version prefix if present
        vector = re.sub(r'^CVSS:3\.[01]/', '', vector_string)

        mappings = {
            'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'},
            'AC': {'L': 'Low', 'H': 'High'},
            'PR': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'UI': {'N': 'None', 'R': 'Required'},
            'S': {'U': 'Unchanged', 'C': 'Changed'},
            'C': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'I': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'A': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'E': {'X': 'Not Defined', 'U': 'Unproven', 'P': 'Proof-of-Concept', 'F': 'Functional', 'H': 'High'},
            'RL': {'X': 'Not Defined', 'O': 'Official Fix', 'T': 'Temporary Fix', 'W': 'Workaround', 'U': 'Unavailable'},
            'RC': {'X': 'Not Defined', 'U': 'Unknown', 'R': 'Reasonable', 'C': 'Confirmed'}
        }

        for part in vector.split('/'):
            if ':' in part:
                key, value = part.split(':')
                if key in mappings and value in mappings[key]:
                    components[key] = mappings[key][value]

        return components

    def calculate_exploitability(self, cvss_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate exploitability metrics"""
        attack_vector = cvss_data.get("attack_vector", "Unknown")
        attack_complexity = cvss_data.get("attack_complexity", "Unknown")
        privileges_required = cvss_data.get("privileges_required", "Unknown")
        user_interaction = cvss_data.get("user_interaction", "Unknown")

        # Exploitability factors
        factors = {
            "remote_exploitable": attack_vector == "Network",
            "low_complexity": attack_complexity == "Low",
            "no_auth_required": privileges_required == "None",
            "no_user_interaction": user_interaction == "None",
        }

        # Calculate risk level
        risk_factors = sum(factors.values())

        if risk_factors >= 4:
            risk_level = "Critical"
            risk_description = "Trivially exploitable remotely without authentication"
        elif risk_factors >= 3:
            risk_level = "High"
            risk_description = "Easily exploitable with minimal requirements"
        elif risk_factors >= 2:
            risk_level = "Medium"
            risk_description = "Exploitable with some requirements"
        else:
            risk_level = "Low"
            risk_description = "Difficult to exploit, requires specific conditions"

        return {
            "exploitability_factors": factors,
            "risk_level": risk_level,
            "risk_description": risk_description,
            "risk_score": risk_factors,
            "attack_surface": "Remote" if attack_vector == "Network" else "Local/Adjacent"
        }

    async def fetch_nvd_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE data from NVD API"""
        cache_key = f"nvd:{cve_id}"

        # Check cache first
        cached = self.redis.get(cache_key)
        if cached:
            return json.loads(cached)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.NVD_API_URL,
                    params={"cveId": cve_id},
                    timeout=30.0,
                    headers={"Accept": "application/json"}
                )

                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    if vulnerabilities:
                        cve_data = vulnerabilities[0].get("cve", {})

                        # Cache the result
                        self.redis.set(
                            cache_key,
                            json.dumps(cve_data),
                            ex=self.CACHE_TTL
                        )

                        return cve_data

        except Exception as e:
            logger.warning(
                "Failed to fetch NVD data",
                cve_id=cve_id,
                error=str(e)
            )

        return None

    def extract_cvss_from_scanner(
        self,
        vuln: Dict[str, Any]
    ) -> Optional[CVSSv3Score]:
        """Extract CVSS data from scanner output"""
        # Try to get CVSS from vulnerability data
        cvss_data = vuln.get("cvss", {})

        if not cvss_data:
            # Try alternate locations
            cvss_data = vuln.get("nvd", {}).get("cvss", {})

        if not cvss_data:
            # Try to get from datasource
            for ds in vuln.get("datasource_specific", {}).values():
                if isinstance(ds, dict) and "cvss" in ds:
                    cvss_data = ds["cvss"]
                    break

        base_score = cvss_data.get("base_score") or cvss_data.get("score") or 0
        vector_string = cvss_data.get("vector") or cvss_data.get("vector_string", "")

        if not base_score and not vector_string:
            # Estimate from severity
            severity = vuln.get("severity", "Unknown").upper()
            severity_scores = {
                "CRITICAL": 9.5,
                "HIGH": 7.5,
                "MEDIUM": 5.5,
                "LOW": 2.5,
                "NEGLIGIBLE": 1.0,
                "UNKNOWN": 0.0
            }
            base_score = severity_scores.get(severity, 0)

        if base_score:
            # Parse vector string if available
            vector_components = self.parse_cvss_vector(vector_string)

            return CVSSv3Score(
                base_score=float(base_score),
                severity=self._score_to_severity(float(base_score)),
                vector_string=vector_string,
                attack_vector=vector_components.get("AV", "Unknown"),
                attack_complexity=vector_components.get("AC", "Unknown"),
                privileges_required=vector_components.get("PR", "Unknown"),
                user_interaction=vector_components.get("UI", "Unknown"),
                scope=vector_components.get("S", "Unknown"),
                confidentiality_impact=vector_components.get("C", "Unknown"),
                integrity_impact=vector_components.get("I", "Unknown"),
                availability_impact=vector_components.get("A", "Unknown"),
                exploit_code_maturity=vector_components.get("E"),
                remediation_level=vector_components.get("RL"),
                report_confidence=vector_components.get("RC")
            )

        return None

    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity rating"""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        else:
            return "None"

    def enrich_vulnerability(
        self,
        vuln: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enrich a single vulnerability with CVSS details"""
        enriched = vuln.copy()

        cvss_score = self.extract_cvss_from_scanner(vuln)

        if cvss_score:
            enriched["cvss"] = {
                "base_score": cvss_score.base_score,
                "severity": cvss_score.severity,
                "vector_string": cvss_score.vector_string,
                "metrics": {
                    "attack_vector": cvss_score.attack_vector,
                    "attack_complexity": cvss_score.attack_complexity,
                    "privileges_required": cvss_score.privileges_required,
                    "user_interaction": cvss_score.user_interaction,
                    "scope": cvss_score.scope,
                    "confidentiality_impact": cvss_score.confidentiality_impact,
                    "integrity_impact": cvss_score.integrity_impact,
                    "availability_impact": cvss_score.availability_impact
                }
            }

            # Calculate exploitability
            exploitability = self.calculate_exploitability(enriched["cvss"]["metrics"])
            enriched["exploitability"] = exploitability

            # Risk prioritization
            enriched["priority_score"] = self._calculate_priority(
                cvss_score.base_score,
                exploitability["risk_score"],
                vuln.get("fix_available", False)
            )

        return enriched

    def _calculate_priority(
        self,
        cvss_score: float,
        exploitability_score: int,
        has_fix: bool
    ) -> Dict[str, Any]:
        """Calculate priority score for remediation"""
        # Weight factors
        cvss_weight = 0.5
        exploit_weight = 0.3
        fix_weight = 0.2

        # Normalize scores
        normalized_cvss = cvss_score / 10.0
        normalized_exploit = exploitability_score / 4.0
        fix_bonus = 1.0 if has_fix else 0.5

        priority = (
            (normalized_cvss * cvss_weight) +
            (normalized_exploit * exploit_weight) +
            (fix_bonus * fix_weight)
        ) * 100

        if priority >= 80:
            priority_level = "P1 - Immediate"
        elif priority >= 60:
            priority_level = "P2 - High"
        elif priority >= 40:
            priority_level = "P3 - Medium"
        else:
            priority_level = "P4 - Low"

        return {
            "score": round(priority, 1),
            "level": priority_level,
            "has_fix": has_fix,
            "recommendation": "Patch immediately" if has_fix and priority >= 60 else
                            "Schedule patching" if has_fix else
                            "Monitor and mitigate"
        }

    def enrich_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich all vulnerabilities with CVSS details"""
        enriched = []

        for vuln in vulnerabilities:
            enriched.append(self.enrich_vulnerability(vuln))

        # Sort by priority score
        enriched.sort(
            key=lambda x: x.get("priority_score", {}).get("score", 0),
            reverse=True
        )

        return enriched

    def get_cvss_summary(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate CVSS summary statistics"""
        total = len(vulnerabilities)
        if total == 0:
            return {"total": 0}

        scores = [v.get("cvss", {}).get("base_score", 0) for v in vulnerabilities]
        exploitability_levels = [
            v.get("exploitability", {}).get("risk_level", "Unknown")
            for v in vulnerabilities
        ]

        remote_exploitable = sum(
            1 for v in vulnerabilities
            if v.get("cvss", {}).get("metrics", {}).get("attack_vector") == "Network"
        )

        no_auth_required = sum(
            1 for v in vulnerabilities
            if v.get("cvss", {}).get("metrics", {}).get("privileges_required") == "None"
        )

        return {
            "total": total,
            "average_cvss": round(sum(scores) / total, 2) if scores else 0,
            "max_cvss": max(scores) if scores else 0,
            "min_cvss": min(scores) if scores else 0,
            "remote_exploitable": remote_exploitable,
            "remote_exploitable_pct": round(remote_exploitable / total * 100, 1),
            "no_auth_required": no_auth_required,
            "no_auth_required_pct": round(no_auth_required / total * 100, 1),
            "by_exploitability": {
                level: exploitability_levels.count(level)
                for level in ["Critical", "High", "Medium", "Low", "Unknown"]
            },
            "priority_breakdown": {
                "P1": sum(1 for v in vulnerabilities if v.get("priority_score", {}).get("level", "").startswith("P1")),
                "P2": sum(1 for v in vulnerabilities if v.get("priority_score", {}).get("level", "").startswith("P2")),
                "P3": sum(1 for v in vulnerabilities if v.get("priority_score", {}).get("level", "").startswith("P3")),
                "P4": sum(1 for v in vulnerabilities if v.get("priority_score", {}).get("level", "").startswith("P4"))
            }
        }
