"""
AI/ML-Assisted Vulnerability Triage Engine
Uses Claude API for intelligent remediation summaries and risk classification.
Gracefully disabled when ANTHROPIC_API_KEY is not set.
"""
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from app.config import settings, get_redis_client
from app.logging_config import get_logger

logger = get_logger(__name__)

# Try importing anthropic SDK
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.info("anthropic SDK not installed — AI triage disabled")

CACHE_TTL = 86400  # 24 hours
CACHE_PREFIX = "ai_triage:"


@dataclass
class TriageResult:
    """AI triage result for a scan"""
    scan_id: str
    risk_classification: str  # "critical_action", "high_priority", "monitor", "accept_risk"
    executive_summary: str
    prioritized_actions: List[Dict[str, Any]]
    exploit_context: str
    remediation_effort: str  # "minimal", "moderate", "significant", "major"
    generated_at: str
    model_used: str
    cached: bool = False


def is_ai_enabled() -> bool:
    """Check if AI triage is available."""
    api_key = _get_api_key()
    return ANTHROPIC_AVAILABLE and bool(api_key)


def _get_api_key() -> Optional[str]:
    """Get Anthropic API key from environment."""
    import os
    return os.environ.get("ANTHROPIC_API_KEY", "")


def _build_vuln_summary(vulnerabilities: List[Dict[str, Any]], scan_data: Dict[str, Any]) -> str:
    """Build a concise vulnerability summary for the AI prompt."""
    severity_counts = {
        "critical": int(scan_data.get("critical", 0)),
        "high": int(scan_data.get("high", 0)),
        "medium": int(scan_data.get("medium", 0)),
        "low": int(scan_data.get("low", 0)),
    }

    # Group vulns by severity, take top ones
    critical_vulns = []
    high_vulns = []
    kev_vulns = []
    high_epss_vulns = []

    for v in vulnerabilities[:500]:  # Limit to avoid token overflow
        severity = v.get("severity", "").lower()
        cve_id = v.get("id", v.get("cve_id", "unknown"))
        pkg = v.get("package", v.get("artifact", {}).get("name", "unknown"))
        version = v.get("version", v.get("artifact", {}).get("version", ""))
        fix = v.get("fix_version", v.get("fixedInVersion", ""))
        epss = v.get("epss_score", v.get("epss", {}).get("epss", 0))
        is_kev = v.get("kev_match", v.get("in_kev", False))

        entry = {
            "cve": cve_id,
            "package": pkg,
            "version": version,
            "fix": fix or "none",
            "epss": round(float(epss), 4) if epss else 0,
            "kev": bool(is_kev),
        }

        if severity == "critical":
            critical_vulns.append(entry)
        elif severity == "high":
            high_vulns.append(entry)
        if is_kev:
            kev_vulns.append(entry)
        if epss and float(epss) > 0.5:
            high_epss_vulns.append(entry)

    image_name = scan_data.get("image_name", "unknown")
    total = scan_data.get("total_unique_vulnerabilities", sum(severity_counts.values()))

    summary = f"""Container Image: {image_name}
Total Vulnerabilities: {total}
Severity Breakdown: Critical={severity_counts['critical']}, High={severity_counts['high']}, Medium={severity_counts['medium']}, Low={severity_counts['low']}
Fixable Critical: {scan_data.get('fixable_critical', 'unknown')}
Fixable High: {scan_data.get('fixable_high', 'unknown')}
Total Packages: {scan_data.get('total_packages', 'unknown')}
Base OS: {scan_data.get('base_image_os', 'unknown')} {scan_data.get('base_image_os_version', '')}
"""

    if kev_vulns:
        summary += f"\nCISA KEV (Known Exploited) Vulnerabilities ({len(kev_vulns)}):\n"
        for v in kev_vulns[:10]:
            summary += f"  - {v['cve']}: {v['package']}@{v['version']} (fix: {v['fix']})\n"

    if high_epss_vulns:
        summary += f"\nHigh EPSS Score (>50% exploit probability) ({len(high_epss_vulns)}):\n"
        for v in high_epss_vulns[:10]:
            summary += f"  - {v['cve']}: {v['package']}@{v['version']} EPSS={v['epss']} (fix: {v['fix']})\n"

    if critical_vulns:
        summary += f"\nCritical Vulnerabilities ({len(critical_vulns)}):\n"
        for v in critical_vulns[:15]:
            summary += f"  - {v['cve']}: {v['package']}@{v['version']} (fix: {v['fix']}) EPSS={v['epss']}\n"

    if high_vulns:
        summary += f"\nHigh Vulnerabilities (top 15 of {len(high_vulns)}):\n"
        for v in high_vulns[:15]:
            summary += f"  - {v['cve']}: {v['package']}@{v['version']} (fix: {v['fix']}) EPSS={v['epss']}\n"

    return summary


def _get_cache_key(scan_id: str) -> str:
    return f"{CACHE_PREFIX}{scan_id}"


def get_cached_triage(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get cached AI triage result."""
    r = get_redis_client()
    cached = r.get(_get_cache_key(scan_id))
    if cached:
        result = json.loads(cached)
        result["cached"] = True
        return result
    return None


def _cache_triage(scan_id: str, result: Dict[str, Any]):
    """Cache AI triage result."""
    r = get_redis_client()
    r.setex(_get_cache_key(scan_id), CACHE_TTL, json.dumps(result))


def generate_triage(
    scan_id: str,
    scan_data: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    force: bool = False,
) -> Dict[str, Any]:
    """
    Generate AI-powered vulnerability triage for a scan.

    Returns a structured triage result with risk classification,
    executive summary, and prioritized remediation actions.
    """
    if not is_ai_enabled():
        return {
            "scan_id": scan_id,
            "error": "AI triage unavailable — set ANTHROPIC_API_KEY to enable",
            "enabled": False,
        }

    # Check cache first
    if not force:
        cached = get_cached_triage(scan_id)
        if cached:
            return cached

    prompt = f"""You are a senior container security engineer performing vulnerability triage.
Analyze the following container scan results and provide a structured triage assessment.

{_build_vuln_summary(vulnerabilities, scan_data)}

Respond in the following JSON format (no markdown, just raw JSON):
{{
  "risk_classification": "critical_action|high_priority|monitor|accept_risk",
  "executive_summary": "2-3 sentence summary of the security posture and most urgent concerns",
  "prioritized_actions": [
    {{
      "priority": 1,
      "action": "specific remediation action",
      "packages": ["package1", "package2"],
      "cves_fixed": ["CVE-xxxx-yyyy"],
      "effort": "minimal|moderate|significant",
      "impact": "description of security impact if not addressed"
    }}
  ],
  "exploit_context": "analysis of real-world exploitability based on EPSS scores and KEV status",
  "remediation_effort": "minimal|moderate|significant|major"
}}

Classification rules:
- critical_action: Any KEV vulnerability, or 3+ critical with fix available, or EPSS > 0.9
- high_priority: Critical vulns with fix, or many high vulns with high EPSS
- monitor: Only medium/low vulns, or no fixes available for critical
- accept_risk: Low/negligible vulns only, all unfixable

Limit prioritized_actions to top 5 most impactful. Focus on actions that fix the most CVEs."""

    try:
        client = anthropic.Anthropic(api_key=_get_api_key())
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = response.content[0].text.strip()
        # Parse JSON from response
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
            response_text = response_text.strip()

        ai_result = json.loads(response_text)

        result = {
            "scan_id": scan_id,
            "risk_classification": ai_result.get("risk_classification", "monitor"),
            "executive_summary": ai_result.get("executive_summary", ""),
            "prioritized_actions": ai_result.get("prioritized_actions", []),
            "exploit_context": ai_result.get("exploit_context", ""),
            "remediation_effort": ai_result.get("remediation_effort", "moderate"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_used": "claude-sonnet-4-20250514",
            "cached": False,
            "enabled": True,
        }

        _cache_triage(scan_id, result)
        logger.info("AI triage generated", scan_id=scan_id, classification=result["risk_classification"])
        return result

    except json.JSONDecodeError as e:
        logger.error("AI triage JSON parse error", error=str(e), scan_id=scan_id)
        return {
            "scan_id": scan_id,
            "error": f"Failed to parse AI response: {str(e)}",
            "enabled": True,
        }
    except Exception as e:
        logger.error("AI triage generation failed", error=str(e), scan_id=scan_id)
        return {
            "scan_id": scan_id,
            "error": f"AI triage failed: {str(e)}",
            "enabled": True,
        }


def generate_remediation_summary(
    scan_id: str,
    scan_data: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Generate a human-readable remediation summary using AI."""
    if not is_ai_enabled():
        return {
            "scan_id": scan_id,
            "error": "AI remediation unavailable — set ANTHROPIC_API_KEY to enable",
            "enabled": False,
        }

    cache_key = f"{CACHE_PREFIX}remediation:{scan_id}"
    r = get_redis_client()
    cached = r.get(cache_key)
    if cached:
        result = json.loads(cached)
        result["cached"] = True
        return result

    prompt = f"""You are a DevSecOps engineer writing a remediation guide for a development team.
Based on the following container vulnerability scan, write a clear, actionable remediation guide.

{_build_vuln_summary(vulnerabilities, scan_data)}

Write a concise remediation guide in JSON format:
{{
  "title": "Remediation Guide for [image name]",
  "risk_level": "critical|high|medium|low",
  "immediate_actions": ["action 1", "action 2"],
  "package_updates": [
    {{
      "package": "name",
      "current": "version",
      "target": "version",
      "cves_fixed": 5,
      "command": "upgrade command"
    }}
  ],
  "base_image_recommendation": "recommendation about base image if applicable",
  "estimated_effort": "time estimate",
  "notes": "any additional context"
}}

Keep it practical. Limit to the 10 most impactful package updates."""

    try:
        client = anthropic.Anthropic(api_key=_get_api_key())
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = response.content[0].text.strip()
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
            response_text = response_text.strip()

        ai_result = json.loads(response_text)
        result = {
            "scan_id": scan_id,
            **ai_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "cached": False,
            "enabled": True,
        }

        r.setex(cache_key, CACHE_TTL, json.dumps(result))
        return result

    except Exception as e:
        logger.error("AI remediation summary failed", error=str(e), scan_id=scan_id)
        return {
            "scan_id": scan_id,
            "error": f"AI remediation failed: {str(e)}",
            "enabled": True,
        }
