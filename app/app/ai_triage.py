"""
AI/ML-Assisted Vulnerability Triage Engine

Supports two providers, selected via env var ``AI_TRIAGE_PROVIDER``:
- ``anthropic``  — Claude via the Anthropic API (requires ANTHROPIC_API_KEY).
- ``openai``     — Any OpenAI-compatible endpoint (local vLLM, Ollama, LM
                    Studio, etc.). Requires AI_TRIAGE_BASE_URL + AI_TRIAGE_MODEL;
                    AI_TRIAGE_API_KEY is optional for self-hosted servers.

If neither provider is configured, AI triage gracefully reports
``enabled: false`` instead of erroring.
"""
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from app.config import get_redis_client
from app.logging_config import get_logger

logger = get_logger(__name__)

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

CACHE_TTL = 86400  # 24 hours
CACHE_PREFIX = "ai_triage:"


@dataclass
class TriageResult:
    scan_id: str
    risk_classification: str
    executive_summary: str
    prioritized_actions: List[Dict[str, Any]]
    exploit_context: str
    remediation_effort: str
    generated_at: str
    model_used: str
    cached: bool = False


# --------------------------------------------------------------------------
# Provider configuration
# --------------------------------------------------------------------------

def _provider() -> str:
    """Resolve the active provider: ``openai``, ``anthropic``, or ``none``."""
    explicit = (os.environ.get("AI_TRIAGE_PROVIDER") or "").strip().lower()
    if explicit in ("openai", "anthropic"):
        return explicit
    # Auto-detect: prefer local OpenAI-compatible if a base URL is set.
    if os.environ.get("AI_TRIAGE_BASE_URL") and OPENAI_AVAILABLE:
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY") and ANTHROPIC_AVAILABLE:
        return "anthropic"
    return "none"


def _model_id() -> str:
    """Resolve the model identifier for the active provider."""
    if _provider() == "openai":
        return os.environ.get("AI_TRIAGE_MODEL", "")
    return os.environ.get("AI_TRIAGE_MODEL", "claude-sonnet-4-20250514")


def is_ai_enabled() -> bool:
    provider = _provider()
    if provider == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if provider == "openai":
        # OpenAI-compatible self-hosted servers often don't need an API key
        return bool(os.environ.get("AI_TRIAGE_BASE_URL")) and bool(_model_id())
    return False


def get_status() -> Dict[str, Any]:
    """Return a small dict describing the current AI triage config."""
    provider = _provider()
    return {
        "enabled": is_ai_enabled(),
        "provider": provider if provider != "none" else None,
        "model": _model_id() if is_ai_enabled() else None,
        "endpoint": os.environ.get("AI_TRIAGE_BASE_URL") if provider == "openai" else None,
    }


# --------------------------------------------------------------------------
# LLM call routing
# --------------------------------------------------------------------------

# Strip Qwen-style <think>...</think> reasoning blocks and common preambles.
# The model sometimes wraps its actual answer in markdown fences too.
_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_LEADING_PREAMBLE = re.compile(
    r"^\s*(?:Here(?:'s| is) (?:a )?(?:thinking process|my answer|the JSON|the response)[^\n{]*\n+)+",
    re.IGNORECASE,
)


def _extract_json(text: str) -> str:
    """Pull a JSON object out of a possibly-noisy LLM response."""
    text = _THINK_BLOCK.sub("", text).strip()
    text = _LEADING_PREAMBLE.sub("", text)

    # Strip ```json ... ``` fences if present.
    if text.startswith("```"):
        # Drop the first fence line and the trailing fence.
        text = text.split("```", 2)
        # text[0] = "", text[1] = "json\n{...}" or "{...}", text[2] = trailing
        body = text[1] if len(text) > 1 else ""
        if body.lower().startswith("json"):
            body = body[4:]
        text = body.strip().rstrip("`").strip()

    # Final fallback: locate the first '{' and the matching last '}'.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    return text


def _call_llm(prompt: str, max_tokens: int = 2000) -> str:
    """Send a single-turn prompt to the configured LLM and return the raw text."""
    provider = _provider()
    if provider == "anthropic":
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        response = client.messages.create(
            model=_model_id(),
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    if provider == "openai":
        client = openai.OpenAI(
            api_key=os.environ.get("AI_TRIAGE_API_KEY", "none"),
            base_url=os.environ["AI_TRIAGE_BASE_URL"].rstrip("/"),
            timeout=120.0,
        )
        # Ask for JSON only — keeps Qwen from preambling. Some local servers
        # don't support response_format, so we tolerate failure and retry plain.
        kwargs = dict(
            model=_model_id(),
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior container security engineer. "
                        "Reply with raw JSON only — no <think> blocks, "
                        "no markdown fences, no commentary."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        try:
            response = client.chat.completions.create(
                response_format={"type": "json_object"}, **kwargs
            )
        except Exception:
            response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""

    raise RuntimeError("No AI provider configured")


# --------------------------------------------------------------------------
# Vulnerability summary builder (unchanged from prior version)
# --------------------------------------------------------------------------

def _build_vuln_summary(vulnerabilities: List[Dict[str, Any]], scan_data: Dict[str, Any]) -> str:
    severity_counts = {
        "critical": int(scan_data.get("critical", 0)),
        "high": int(scan_data.get("high", 0)),
        "medium": int(scan_data.get("medium", 0)),
        "low": int(scan_data.get("low", 0)),
    }

    critical_vulns, high_vulns, kev_vulns, high_epss_vulns = [], [], [], []
    for v in vulnerabilities[:500]:
        severity = v.get("severity", "").lower()
        cve_id = v.get("id", v.get("cve_id", "unknown"))
        pkg = v.get("package", v.get("artifact", {}).get("name", "unknown"))
        version = v.get("version", v.get("artifact", {}).get("version", ""))
        fix = v.get("fix_version", v.get("fixedInVersion", ""))
        epss = v.get("epss_score", v.get("epss", {}).get("epss", 0))
        is_kev = v.get("kev_match", v.get("in_kev", False))

        entry = {
            "cve": cve_id, "package": pkg, "version": version,
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


# --------------------------------------------------------------------------
# Cache helpers
# --------------------------------------------------------------------------

def _get_cache_key(scan_id: str) -> str:
    return f"{CACHE_PREFIX}{scan_id}"


def get_cached_triage(scan_id: str) -> Optional[Dict[str, Any]]:
    r = get_redis_client()
    cached = r.get(_get_cache_key(scan_id))
    if cached:
        result = json.loads(cached)
        result["cached"] = True
        return result
    return None


def _cache_triage(scan_id: str, result: Dict[str, Any]):
    r = get_redis_client()
    r.setex(_get_cache_key(scan_id), CACHE_TTL, json.dumps(result))


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def generate_triage(
    scan_id: str,
    scan_data: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    force: bool = False,
) -> Dict[str, Any]:
    if not is_ai_enabled():
        return {
            "scan_id": scan_id,
            "error": "AI triage unavailable — configure AI_TRIAGE_PROVIDER (anthropic or openai)",
            "enabled": False,
        }

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
        raw = _call_llm(prompt, max_tokens=2000)
        ai_result = json.loads(_extract_json(raw))

        result = {
            "scan_id": scan_id,
            "risk_classification": ai_result.get("risk_classification", "monitor"),
            "executive_summary": ai_result.get("executive_summary", ""),
            "prioritized_actions": ai_result.get("prioritized_actions", []),
            "exploit_context": ai_result.get("exploit_context", ""),
            "remediation_effort": ai_result.get("remediation_effort", "moderate"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_used": _model_id(),
            "provider": _provider(),
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
    if not is_ai_enabled():
        return {
            "scan_id": scan_id,
            "error": "AI remediation unavailable — configure AI_TRIAGE_PROVIDER (anthropic or openai)",
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
        raw = _call_llm(prompt, max_tokens=2000)
        ai_result = json.loads(_extract_json(raw))
        result = {
            "scan_id": scan_id,
            **ai_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_used": _model_id(),
            "provider": _provider(),
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
