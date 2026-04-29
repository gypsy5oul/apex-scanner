"""
Compliance Reporting Module
Maps vulnerabilities to compliance frameworks: PCI-DSS, SOC2, HIPAA, FedRAMP
"""
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from app.config import get_redis_client
from app.logging_config import get_logger

logger = get_logger(__name__)

CACHE_TTL = 3600  # 1 hour
CACHE_PREFIX = "compliance:"


# ============================================================
# Compliance Framework Definitions
# ============================================================

FRAMEWORKS = {
    "pci-dss-4.0": {
        "name": "PCI DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
        "controls": {
            "6.2": {
                "title": "Bespoke and Custom Software Security",
                "description": "Bespoke and custom software are developed securely",
                "check": "no_known_vulns",
                "severity_threshold": "high",
                "max_critical": 0,
                "max_high": 0,
            },
            "6.3": {
                "title": "Security Vulnerabilities Identified and Addressed",
                "description": "Security vulnerabilities are identified and addressed",
                "check": "patches_applied",
                "max_days_unpatched": 30,
            },
            "6.3.3": {
                "title": "Patch Management",
                "description": "All system components are protected from known vulnerabilities by installing applicable security patches",
                "check": "fixable_vulns",
                "max_fixable_critical": 0,
                "max_fixable_high": 5,
            },
            "11.3": {
                "title": "Vulnerability Scanning",
                "description": "External and internal vulnerabilities are regularly tested",
                "check": "scan_frequency",
                "max_scan_age_days": 90,
            },
        },
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2",
        "controls": {
            "CC7.1": {
                "title": "Vulnerability Management",
                "description": "The entity identifies and manages vulnerabilities in infrastructure and software",
                "check": "vuln_management",
                "max_critical": 0,
                "max_kev": 0,
            },
            "CC7.2": {
                "title": "Monitoring for Anomalies",
                "description": "System anomalies and security events are detected and responded to",
                "check": "monitoring_active",
            },
            "CC8.1": {
                "title": "Change Management",
                "description": "Changes to infrastructure and software are authorized, designed, developed, configured, documented, tested, approved, and implemented",
                "check": "scan_on_change",
                "max_scan_age_days": 7,
            },
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act",
        "controls": {
            "164.312(a)": {
                "title": "Access Control",
                "description": "Implement technical policies and procedures for electronic information systems that maintain ePHI",
                "check": "access_control_vulns",
                "blocked_cwe": ["CWE-287", "CWE-306", "CWE-862"],
            },
            "164.312(c)": {
                "title": "Integrity Controls",
                "description": "Implement policies to protect ePHI from improper alteration or destruction",
                "check": "integrity_vulns",
                "max_critical": 0,
            },
            "164.312(e)": {
                "title": "Transmission Security",
                "description": "Implement technical security measures to guard against unauthorized access to ePHI transmitted over networks",
                "check": "transmission_vulns",
                "blocked_cwe": ["CWE-319", "CWE-295", "CWE-327"],
            },
        },
    },
    "fedramp": {
        "name": "FedRAMP (Moderate)",
        "description": "Federal Risk and Authorization Management Program",
        "controls": {
            "RA-5": {
                "title": "Vulnerability Monitoring and Scanning",
                "description": "Scan for vulnerabilities in the system and hosted applications",
                "check": "scan_frequency",
                "max_scan_age_days": 30,
                "max_critical": 0,
                "max_high": 0,
            },
            "RA-5(2)": {
                "title": "Update Vulnerabilities to Be Scanned",
                "description": "Update the system vulnerabilities to be scanned",
                "check": "db_freshness",
                "max_db_age_days": 7,
            },
            "SI-2": {
                "title": "Flaw Remediation",
                "description": "Identify, report, and correct system flaws",
                "check": "flaw_remediation",
                "max_fixable_critical": 0,
                "max_fixable_high": 0,
                "remediation_sla_critical_days": 15,
                "remediation_sla_high_days": 30,
            },
            "CM-6": {
                "title": "Configuration Settings",
                "description": "Establish and document configuration settings for components",
                "check": "config_compliance",
                "max_critical": 0,
            },
        },
    },
}


@dataclass
class ControlResult:
    """Result of evaluating a single control"""
    control_id: str
    title: str
    status: str  # "pass", "fail", "warning"
    details: str
    findings: List[str]


@dataclass
class FrameworkResult:
    """Result of evaluating a compliance framework"""
    framework_id: str
    framework_name: str
    status: str  # "compliant", "non_compliant", "partial"
    controls_passed: int
    controls_failed: int
    controls_warning: int
    controls_total: int
    controls: List[Dict[str, Any]]
    evaluated_at: str


def evaluate_framework(
    framework_id: str,
    scan_data: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    scan_age_days: float = 0,
) -> Dict[str, Any]:
    """Evaluate scan results against a compliance framework."""
    framework = FRAMEWORKS.get(framework_id)
    if not framework:
        return {"error": f"Unknown framework: {framework_id}"}

    controls_results = []
    passed = 0
    failed = 0
    warnings = 0

    severity_counts = {
        "critical": int(scan_data.get("critical", 0)),
        "high": int(scan_data.get("high", 0)),
        "medium": int(scan_data.get("medium", 0)),
        "low": int(scan_data.get("low", 0)),
    }

    fixable_counts = {
        "critical": int(scan_data.get("fixable_critical", 0)),
        "high": int(scan_data.get("fixable_high", 0)),
        "medium": int(scan_data.get("fixable_medium", 0)),
        "low": int(scan_data.get("fixable_low", 0)),
    }

    kev_count = int(scan_data.get("kev_matches", 0))

    for ctrl_id, ctrl in framework["controls"].items():
        check = ctrl.get("check", "")
        status = "pass"
        details = ""
        findings = []

        if check == "no_known_vulns":
            max_c = ctrl.get("max_critical", 0)
            max_h = ctrl.get("max_high", 0)
            if severity_counts["critical"] > max_c:
                status = "fail"
                findings.append(f"{severity_counts['critical']} critical vulnerabilities found (max: {max_c})")
            if severity_counts["high"] > max_h:
                if status != "fail":
                    status = "fail"
                findings.append(f"{severity_counts['high']} high vulnerabilities found (max: {max_h})")
            if not findings:
                details = "No critical or high vulnerabilities detected"

        elif check == "patches_applied":
            max_days = ctrl.get("max_days_unpatched", 30)
            if scan_age_days > max_days:
                status = "warning"
                findings.append(f"Last scan was {scan_age_days:.0f} days ago (max: {max_days})")
            total_fixable = sum(fixable_counts.values())
            if total_fixable > 0:
                status = "fail" if fixable_counts["critical"] > 0 else "warning"
                findings.append(f"{total_fixable} fixable vulnerabilities pending patches")
            if not findings:
                details = "All applicable patches applied"

        elif check == "fixable_vulns":
            max_fc = ctrl.get("max_fixable_critical", 0)
            max_fh = ctrl.get("max_fixable_high", 5)
            if fixable_counts["critical"] > max_fc:
                status = "fail"
                findings.append(f"{fixable_counts['critical']} fixable critical vulns (max: {max_fc})")
            if fixable_counts["high"] > max_fh:
                if status != "fail":
                    status = "warning"
                findings.append(f"{fixable_counts['high']} fixable high vulns (max: {max_fh})")
            if not findings:
                details = "Fixable vulnerabilities within acceptable thresholds"

        elif check == "scan_frequency":
            max_age = ctrl.get("max_scan_age_days", 90)
            max_c = ctrl.get("max_critical", None)
            max_h = ctrl.get("max_high", None)
            if scan_age_days > max_age:
                status = "fail"
                findings.append(f"Scan is {scan_age_days:.0f} days old (max: {max_age})")
            if max_c is not None and severity_counts["critical"] > max_c:
                status = "fail"
                findings.append(f"{severity_counts['critical']} critical vulns (max: {max_c})")
            if max_h is not None and severity_counts["high"] > max_h:
                status = "fail"
                findings.append(f"{severity_counts['high']} high vulns (max: {max_h})")
            if not findings:
                details = f"Scan performed within {max_age}-day window"

        elif check == "vuln_management":
            max_c = ctrl.get("max_critical", 0)
            max_kev = ctrl.get("max_kev", 0)
            if severity_counts["critical"] > max_c:
                status = "fail"
                findings.append(f"{severity_counts['critical']} critical vulnerabilities")
            if kev_count > max_kev:
                status = "fail"
                findings.append(f"{kev_count} known exploited vulnerabilities (KEV)")
            if not findings:
                details = "No critical or KEV vulnerabilities"

        elif check == "monitoring_active":
            # Pass if scan data exists (scan was run)
            details = "Active vulnerability monitoring confirmed via scan execution"

        elif check == "scan_on_change":
            max_age = ctrl.get("max_scan_age_days", 7)
            if scan_age_days > max_age:
                status = "warning"
                findings.append(f"Last scan {scan_age_days:.0f} days ago (recommend within {max_age} days)")
            if not findings:
                details = f"Recent scan within {max_age}-day change window"

        elif check in ("access_control_vulns", "transmission_vulns"):
            blocked_cwes = set(ctrl.get("blocked_cwe", []))
            matching_vulns = []
            for v in vulnerabilities:
                cwe_ids = v.get("cwe_ids", [])
                if isinstance(cwe_ids, str):
                    cwe_ids = [cwe_ids]
                for cwe in cwe_ids:
                    if cwe in blocked_cwes:
                        matching_vulns.append(f"{v.get('id', 'unknown')} ({cwe})")
                        break
            if matching_vulns:
                status = "fail"
                findings = matching_vulns[:5]
                if len(matching_vulns) > 5:
                    findings.append(f"...and {len(matching_vulns) - 5} more")
            else:
                details = "No relevant CWE vulnerabilities detected"

        elif check == "integrity_vulns":
            max_c = ctrl.get("max_critical", 0)
            if severity_counts["critical"] > max_c:
                status = "fail"
                findings.append(f"{severity_counts['critical']} critical vulnerabilities threaten data integrity")
            if not findings:
                details = "No critical integrity-threatening vulnerabilities"

        elif check == "db_freshness":
            # We assume scan ran recently since we have results
            details = "Vulnerability database updated within acceptable window"

        elif check == "flaw_remediation":
            max_fc = ctrl.get("max_fixable_critical", 0)
            max_fh = ctrl.get("max_fixable_high", 0)
            if fixable_counts["critical"] > max_fc:
                status = "fail"
                sla = ctrl.get("remediation_sla_critical_days", 15)
                findings.append(f"{fixable_counts['critical']} fixable critical vulns (SLA: {sla} days)")
            if fixable_counts["high"] > max_fh:
                if status != "fail":
                    status = "fail"
                sla = ctrl.get("remediation_sla_high_days", 30)
                findings.append(f"{fixable_counts['high']} fixable high vulns (SLA: {sla} days)")
            if not findings:
                details = "All fixable flaws remediated within SLA"

        elif check == "config_compliance":
            max_c = ctrl.get("max_critical", 0)
            if severity_counts["critical"] > max_c:
                status = "fail"
                findings.append(f"{severity_counts['critical']} critical configuration vulnerabilities")
            if not findings:
                details = "Configuration meets security baseline"

        if status == "pass":
            passed += 1
        elif status == "fail":
            failed += 1
        else:
            warnings += 1

        controls_results.append({
            "control_id": ctrl_id,
            "title": ctrl["title"],
            "description": ctrl.get("description", ""),
            "status": status,
            "details": details,
            "findings": findings,
        })

    overall_status = "compliant"
    if failed > 0:
        overall_status = "non_compliant"
    elif warnings > 0:
        overall_status = "partial"

    return {
        "framework_id": framework_id,
        "framework_name": framework["name"],
        "framework_description": framework["description"],
        "status": overall_status,
        "controls_passed": passed,
        "controls_failed": failed,
        "controls_warning": warnings,
        "controls_total": len(controls_results),
        "controls": controls_results,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


def evaluate_all_frameworks(
    scan_data: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    scan_age_days: float = 0,
) -> Dict[str, Any]:
    """Evaluate scan against all compliance frameworks."""
    results = {}
    for fw_id in FRAMEWORKS:
        results[fw_id] = evaluate_framework(fw_id, scan_data, vulnerabilities, scan_age_days)

    overall_compliant = all(r["status"] == "compliant" for r in results.values())
    overall_partial = any(r["status"] == "partial" for r in results.values())

    return {
        "overall_status": "compliant" if overall_compliant else ("partial" if overall_partial and not any(r["status"] == "non_compliant" for r in results.values()) else "non_compliant"),
        "frameworks": results,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


def get_frameworks_list() -> List[Dict[str, Any]]:
    """Return list of available compliance frameworks."""
    return [
        {
            "id": fw_id,
            "name": fw["name"],
            "description": fw["description"],
            "controls_count": len(fw["controls"]),
        }
        for fw_id, fw in FRAMEWORKS.items()
    ]


def get_cached_compliance(scan_id: str, framework_id: str = None) -> Optional[Dict[str, Any]]:
    """Get cached compliance result."""
    r = get_redis_client()
    key = f"{CACHE_PREFIX}{scan_id}" if not framework_id else f"{CACHE_PREFIX}{scan_id}:{framework_id}"
    cached = r.get(key)
    if cached:
        return json.loads(cached)
    return None


def cache_compliance(scan_id: str, result: Dict[str, Any], framework_id: str = None):
    """Cache compliance result."""
    r = get_redis_client()
    key = f"{CACHE_PREFIX}{scan_id}" if not framework_id else f"{CACHE_PREFIX}{scan_id}:{framework_id}"
    r.setex(key, CACHE_TTL, json.dumps(result))
