"""
Remediation Suggestions Engine
Provides actionable fix recommendations for vulnerabilities
"""
import json
import redis
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
from datetime import datetime

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


@dataclass
class RemediationAction:
    """A specific remediation action"""
    package_name: str
    current_version: str
    fixed_version: str
    action_type: str  # "upgrade", "patch", "replace", "remove"
    priority: str  # "critical", "high", "medium", "low"
    vulnerabilities_fixed: List[str]
    severity_breakdown: Dict[str, int]
    effort_estimate: str  # "minimal", "moderate", "significant"
    breaking_change_risk: str  # "low", "medium", "high"
    command: str  # Suggested command to fix


class RemediationEngine:
    """Generates remediation suggestions for scan results"""

    # Package manager commands for different ecosystems
    PACKAGE_MANAGERS = {
        "npm": {
            "upgrade": "npm install {package}@{version}",
            "audit_fix": "npm audit fix",
            "force_fix": "npm audit fix --force"
        },
        "pip": {
            "upgrade": "pip install {package}=={version}",
            "upgrade_all": "pip install --upgrade {package}"
        },
        "gem": {
            "upgrade": "gem update {package} -v {version}",
            "bundle": "bundle update {package}"
        },
        "maven": {
            "upgrade": "Update pom.xml: <version>{version}</version>",
            "note": "Run: mvn versions:use-latest-versions"
        },
        "gradle": {
            "upgrade": "Update build.gradle: implementation '{package}:{version}'",
            "note": "Run: ./gradlew dependencyUpdates"
        },
        "rpm": {
            "upgrade": "yum update {package}",
            "dnf": "dnf upgrade {package}"
        },
        "deb": {
            "upgrade": "apt-get install {package}={version}",
            "apt": "apt install {package}={version}"
        },
        "apk": {
            "upgrade": "apk upgrade {package}",
            "add": "apk add {package}={version}"
        },
        "go": {
            "upgrade": "go get {package}@v{version}",
            "mod": "go mod tidy && go get -u {package}"
        },
        "cargo": {
            "upgrade": "cargo update -p {package}",
            "edit": "Update Cargo.toml: {package} = \"{version}\""
        },
        "nuget": {
            "upgrade": "dotnet add package {package} --version {version}",
            "update": "Update-Package {package} -Version {version}"
        }
    }

    def __init__(self):
        self.redis = get_redis_client()

    def generate_remediation_plan(self, scan_id: str) -> Dict[str, Any]:
        """
        Generate a comprehensive remediation plan for a scan

        Args:
            scan_id: The scan ID to generate remediation for

        Returns:
            Remediation plan with prioritized actions
        """
        # Check cache first (cache for 1 hour)
        cache_key = f"remediation:{scan_id}"
        cached = self.redis.get(cache_key)
        if cached:
            return json.loads(cached)

        # Get vulnerability data
        vulns_key = f"vulns:{scan_id}"
        vulns_data = self.redis.get(vulns_key)

        if not vulns_data:
            return {"error": "Scan results not found"}

        vulnerabilities = json.loads(vulns_data)

        # Group vulnerabilities by package
        package_vulns = self._group_by_package(vulnerabilities)

        # Generate remediation actions
        actions = []
        for pkg_key, vulns in package_vulns.items():
            action = self._create_remediation_action(pkg_key, vulns)
            if action:
                actions.append(action)

        # Sort by priority
        actions.sort(key=lambda a: (
            self._priority_score(a["priority"]),
            -a["severity_breakdown"].get("critical", 0),
            -a["severity_breakdown"].get("high", 0),
            -len(a["vulnerabilities_fixed"])
        ))

        # Generate summary
        summary = self._generate_summary(actions, vulnerabilities)

        # Generate commands script
        script = self._generate_remediation_script(actions)

        result = {
            "scan_id": scan_id,
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "actions": actions,
            "remediation_script": script,
            "quick_wins": self._identify_quick_wins(actions),
            "upgrade_paths": self._suggest_upgrade_paths(actions)
        }

        # Cache result for 1 hour
        self.redis.setex(cache_key, 3600, json.dumps(result))

        return result

    def _group_by_package(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by package name and version"""
        grouped = defaultdict(list)
        for vuln in vulnerabilities:
            pkg_name = vuln.get("package_name") or vuln.get("package", "unknown")
            pkg_version = vuln.get("package_version") or vuln.get("version", "unknown")
            pkg_type = vuln.get("package_type") or vuln.get("type", "unknown")
            key = f"{pkg_type}:{pkg_name}:{pkg_version}"
            grouped[key].append(vuln)
        return grouped

    def _create_remediation_action(
        self,
        pkg_key: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Create a remediation action for a package"""
        parts = pkg_key.split(":", 2)
        pkg_type = parts[0] if len(parts) > 0 else "unknown"
        pkg_name = parts[1] if len(parts) > 1 else "unknown"
        current_version = parts[2] if len(parts) > 2 else "unknown"

        # Find the best fix version (highest version that fixes all vulns)
        fix_versions = []
        for vuln in vulnerabilities:
            # Check multiple possible field names for fix version
            fix_ver = vuln.get("fix_version") or vuln.get("fixed_in")
            if not fix_ver:
                # Check for fix_versions array
                fix_vers_list = vuln.get("fix_versions", [])
                if isinstance(fix_vers_list, list) and fix_vers_list:
                    fix_ver = fix_vers_list[0]  # Take first fix version
            if fix_ver and fix_ver != "unknown" and fix_ver != "":
                fix_versions.append(fix_ver)

        # Get the highest fix version
        fixed_version = self._get_highest_version(fix_versions) if fix_versions else None

        # Count severities
        severity_breakdown = defaultdict(int)
        vuln_ids = []
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            severity_breakdown[severity] += 1
            vuln_ids.append(vuln.get("id", "unknown"))

        # Determine priority
        if severity_breakdown.get("critical", 0) > 0:
            priority = "critical"
        elif severity_breakdown.get("high", 0) > 0:
            priority = "high"
        elif severity_breakdown.get("medium", 0) > 0:
            priority = "medium"
        else:
            priority = "low"

        # Determine action type
        if fixed_version:
            action_type = "upgrade"
            effort = self._estimate_upgrade_effort(current_version, fixed_version)
            breaking_risk = self._estimate_breaking_risk(current_version, fixed_version)
        else:
            action_type = "investigate"
            effort = "unknown"
            breaking_risk = "unknown"

        # Get package manager command
        command = self._get_upgrade_command(pkg_type, pkg_name, fixed_version)

        return {
            "package_name": pkg_name,
            "package_type": pkg_type,
            "current_version": current_version,
            "fixed_version": fixed_version,
            "action_type": action_type,
            "priority": priority,
            "vulnerabilities_fixed": vuln_ids,
            "vulnerability_count": len(vuln_ids),
            "severity_breakdown": dict(severity_breakdown),
            "effort_estimate": effort,
            "breaking_change_risk": breaking_risk,
            "command": command,
            "has_fix": fixed_version is not None
        }

    def _get_highest_version(self, versions: List[str]) -> Optional[str]:
        """Get the highest semantic version from a list"""
        if not versions:
            return None

        def parse_version(v: str) -> Tuple:
            # Remove common prefixes
            v = re.sub(r'^[v=]', '', v)
            # Split by common delimiters
            parts = re.split(r'[.\-_]', v)
            result = []
            for p in parts:
                try:
                    result.append(int(re.sub(r'[^\d]', '', p) or 0))
                except ValueError:
                    result.append(0)
            return tuple(result)

        try:
            return max(versions, key=parse_version)
        except Exception:
            return versions[0] if versions else None

    def _estimate_upgrade_effort(self, current: str, target: str) -> str:
        """Estimate the effort required for an upgrade"""
        try:
            current_parts = re.split(r'[.\-_]', re.sub(r'^[v=]', '', current))
            target_parts = re.split(r'[.\-_]', re.sub(r'^[v=]', '', target))

            current_major = int(re.sub(r'[^\d]', '', current_parts[0]) or 0)
            target_major = int(re.sub(r'[^\d]', '', target_parts[0]) or 0)

            if target_major > current_major:
                return "significant"  # Major version upgrade
            elif len(current_parts) > 1 and len(target_parts) > 1:
                current_minor = int(re.sub(r'[^\d]', '', current_parts[1]) or 0)
                target_minor = int(re.sub(r'[^\d]', '', target_parts[1]) or 0)
                if target_minor > current_minor + 5:
                    return "moderate"  # Many minor versions
            return "minimal"  # Patch or few minor versions
        except Exception:
            return "unknown"

    def _estimate_breaking_risk(self, current: str, target: str) -> str:
        """Estimate the risk of breaking changes"""
        try:
            current_parts = re.split(r'[.\-_]', re.sub(r'^[v=]', '', current))
            target_parts = re.split(r'[.\-_]', re.sub(r'^[v=]', '', target))

            current_major = int(re.sub(r'[^\d]', '', current_parts[0]) or 0)
            target_major = int(re.sub(r'[^\d]', '', target_parts[0]) or 0)

            if target_major > current_major:
                return "high"  # Major version = likely breaking changes
            elif len(current_parts) > 1 and len(target_parts) > 1:
                current_minor = int(re.sub(r'[^\d]', '', current_parts[1]) or 0)
                target_minor = int(re.sub(r'[^\d]', '', target_parts[1]) or 0)
                if target_minor > current_minor + 3:
                    return "medium"
            return "low"
        except Exception:
            return "unknown"

    def _priority_score(self, priority: str) -> int:
        """Convert priority to numeric score for sorting"""
        scores = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return scores.get(priority, 4)

    def _get_upgrade_command(
        self,
        pkg_type: str,
        pkg_name: str,
        version: Optional[str]
    ) -> str:
        """Get the appropriate upgrade command for a package"""
        pkg_type_lower = pkg_type.lower()

        # Map package types to package managers
        type_mapping = {
            "npm": "npm",
            "node": "npm",
            "python": "pip",
            "pip": "pip",
            "pypi": "pip",
            "gem": "gem",
            "ruby": "gem",
            "maven": "maven",
            "java": "maven",
            "gradle": "gradle",
            "rpm": "rpm",
            "yum": "rpm",
            "deb": "deb",
            "dpkg": "deb",
            "apt": "deb",
            "apk": "apk",
            "alpine": "apk",
            "go": "go",
            "golang": "go",
            "cargo": "cargo",
            "rust": "cargo",
            "nuget": "nuget",
            "dotnet": "nuget"
        }

        manager = type_mapping.get(pkg_type_lower, pkg_type_lower)
        commands = self.PACKAGE_MANAGERS.get(manager, {})

        if version and "upgrade" in commands:
            return commands["upgrade"].format(package=pkg_name, version=version)
        elif "upgrade" in commands:
            return commands.get("upgrade_all", commands["upgrade"]).format(
                package=pkg_name, version="latest"
            )

        return f"# Manual update required for {pkg_name}"

    def _generate_summary(
        self,
        actions: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate a summary of the remediation plan"""
        total_vulns = len(vulnerabilities)
        fixable_vulns = sum(
            a["vulnerability_count"]
            for a in actions
            if a.get("has_fix")
        )

        packages_to_update = sum(1 for a in actions if a.get("has_fix"))
        critical_actions = sum(1 for a in actions if a["priority"] == "critical")
        high_actions = sum(1 for a in actions if a["priority"] == "high")

        return {
            "total_vulnerabilities": total_vulns,
            "fixable_vulnerabilities": fixable_vulns,
            "unfixable_vulnerabilities": total_vulns - fixable_vulns,
            "fix_coverage_percentage": round(fixable_vulns / total_vulns * 100, 1) if total_vulns > 0 else 0,
            "packages_requiring_update": packages_to_update,
            "critical_priority_actions": critical_actions,
            "high_priority_actions": high_actions,
            "estimated_remediation_time": self._estimate_total_time(actions)
        }

    def _estimate_total_time(self, actions: List[Dict[str, Any]]) -> str:
        """Estimate total time to implement all remediations"""
        minimal = sum(1 for a in actions if a.get("effort_estimate") == "minimal")
        moderate = sum(1 for a in actions if a.get("effort_estimate") == "moderate")
        significant = sum(1 for a in actions if a.get("effort_estimate") == "significant")

        # Rough estimates: minimal=5min, moderate=30min, significant=2hr
        total_minutes = minimal * 5 + moderate * 30 + significant * 120

        if total_minutes < 60:
            return f"{total_minutes} minutes"
        elif total_minutes < 480:
            return f"{round(total_minutes / 60, 1)} hours"
        else:
            return f"{round(total_minutes / 480, 1)} days"

    def _identify_quick_wins(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify quick wins - high impact, low effort remediations"""
        quick_wins = []

        for action in actions:
            if (action.get("effort_estimate") == "minimal" and
                action.get("breaking_change_risk") == "low" and
                action.get("has_fix") and
                (action["priority"] in ["critical", "high"] or
                 action["vulnerability_count"] >= 3)):
                quick_wins.append({
                    "package": action["package_name"],
                    "current": action["current_version"],
                    "target": action["fixed_version"],
                    "vulns_fixed": action["vulnerability_count"],
                    "command": action["command"],
                    "reason": f"Fixes {action['vulnerability_count']} vulnerabilities with minimal effort"
                })

        return quick_wins[:10]  # Top 10 quick wins

    def _suggest_upgrade_paths(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Suggest optimal upgrade paths to minimize breaking changes"""
        # Group by package type
        by_type = defaultdict(list)
        for action in actions:
            if action.get("has_fix"):
                by_type[action["package_type"]].append(action)

        paths = []
        for pkg_type, type_actions in by_type.items():
            # Sort by effort
            safe_first = sorted(
                type_actions,
                key=lambda a: (
                    self._priority_score(a.get("breaking_change_risk", "unknown")),
                    -a["vulnerability_count"]
                )
            )

            if safe_first:
                paths.append({
                    "package_type": pkg_type,
                    "total_packages": len(safe_first),
                    "recommended_order": [
                        {"package": a["package_name"], "to_version": a["fixed_version"]}
                        for a in safe_first[:5]
                    ],
                    "total_vulns_fixed": sum(a["vulnerability_count"] for a in safe_first)
                })

        return paths

    def _generate_remediation_script(self, actions: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate shell scripts for automated remediation"""
        scripts = defaultdict(list)

        for action in actions:
            if action.get("has_fix") and action.get("command"):
                pkg_type = action.get("package_type", "other")
                scripts[pkg_type].append(f"# Fix {action['package_name']}: {action['vulnerability_count']} vulnerabilities")
                scripts[pkg_type].append(action["command"])
                scripts[pkg_type].append("")

        result = {}
        for pkg_type, commands in scripts.items():
            result[pkg_type] = "\n".join(commands)

        # Add combined script
        all_commands = []
        all_commands.append("#!/bin/bash")
        all_commands.append("# Auto-generated remediation script")
        all_commands.append(f"# Generated: {datetime.now().isoformat()}")
        all_commands.append("")

        for pkg_type, commands in scripts.items():
            all_commands.append(f"# === {pkg_type.upper()} Packages ===")
            all_commands.extend(commands)  # commands is already a list
            all_commands.append("")

        result["combined"] = "\n".join(all_commands)

        return result

    def get_package_alternatives(self, package_name: str, package_type: str) -> Dict[str, Any]:
        """
        Suggest alternative packages if the current one has unfixable vulnerabilities

        This is a placeholder that could be enhanced with a package database
        """
        # Common package alternatives (simplified)
        alternatives = {
            "request": ["axios", "node-fetch", "got"],
            "moment": ["dayjs", "date-fns", "luxon"],
            "lodash": ["ramda", "underscore"],
            "express": ["fastify", "koa", "hapi"],
        }

        alt_list = alternatives.get(package_name.lower(), [])

        return {
            "package": package_name,
            "type": package_type,
            "alternatives": alt_list,
            "note": "Consider these alternatives if vulnerabilities cannot be fixed by upgrading"
        }
