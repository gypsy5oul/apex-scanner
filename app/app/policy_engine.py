"""
Policy Engine for Security Gates
Define policies to pass/fail scans based on vulnerability severity, EPSS scores, KEV matches, etc.
"""
import json
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum

from app.config import settings, get_redis_client
from app.logging_config import get_logger

logger = get_logger(__name__)

POLICIES_KEY = "apex:policies"
POLICY_PREFIX = "apex:policy:"


class PolicyAction(str, Enum):
    FAIL = "fail"
    WARN = "warn"
    PASS = "pass"


class RuleOperator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_OR_EQUAL = "greater_or_equal"
    LESS_OR_EQUAL = "less_or_equal"
    CONTAINS = "contains"
    IN = "in"


@dataclass
class PolicyRule:
    """Single policy rule"""
    field: str  # e.g., "severity", "epss_score", "in_kev", "license"
    operator: str
    value: Any
    action: str  # "fail", "warn", "pass"
    description: Optional[str] = None


@dataclass
class Policy:
    """Security policy definition"""
    id: str
    name: str
    description: str
    enabled: bool
    rules: List[Dict[str, Any]]
    created_at: str
    updated_at: str
    fail_on_warn: bool = False  # If true, warnings also fail the gate
    apply_to: List[str] = None  # List of image patterns to apply to, None = all


@dataclass
class PolicyViolation:
    """Policy violation details"""
    rule: Dict[str, Any]
    action: str
    message: str
    matched_items: List[Dict[str, Any]]


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation"""
    policy_id: str
    policy_name: str
    passed: bool
    status: str  # "passed", "failed", "warning"
    violations: List[Dict[str, Any]]
    summary: Dict[str, int]
    evaluated_at: str


class PolicyEngine:
    """Policy engine for security gates"""

    def __init__(self):
        self._ensure_default_policies()

    def _ensure_default_policies(self):
        """Create default policies if none exist"""
        policies = self.list_policies()
        if not policies:
            # Create default production policy
            self.create_policy(
                name="Production Security Gate",
                description="Strict policy for production deployments - fails on critical/high vulns or KEV matches",
                rules=[
                    {
                        "field": "severity",
                        "operator": "equals",
                        "value": "CRITICAL",
                        "action": "fail",
                        "description": "Fail on critical vulnerabilities"
                    },
                    {
                        "field": "severity",
                        "operator": "equals",
                        "value": "HIGH",
                        "action": "fail",
                        "description": "Fail on high vulnerabilities"
                    },
                    {
                        "field": "in_kev",
                        "operator": "equals",
                        "value": True,
                        "action": "fail",
                        "description": "Fail on known exploited vulnerabilities"
                    },
                    {
                        "field": "epss_score",
                        "operator": "greater_than",
                        "value": 0.7,
                        "action": "fail",
                        "description": "Fail on EPSS score > 0.7"
                    },
                    {
                        "field": "severity",
                        "operator": "equals",
                        "value": "MEDIUM",
                        "action": "warn",
                        "description": "Warn on medium vulnerabilities"
                    }
                ],
                enabled=True
            )

            # Create default development policy
            self.create_policy(
                name="Development Security Gate",
                description="Relaxed policy for development - fails only on critical vulns or active exploits",
                rules=[
                    {
                        "field": "severity",
                        "operator": "equals",
                        "value": "CRITICAL",
                        "action": "fail",
                        "description": "Fail on critical vulnerabilities"
                    },
                    {
                        "field": "in_kev",
                        "operator": "equals",
                        "value": True,
                        "action": "fail",
                        "description": "Fail on known exploited vulnerabilities"
                    },
                    {
                        "field": "epss_score",
                        "operator": "greater_than",
                        "value": 0.9,
                        "action": "fail",
                        "description": "Fail on EPSS score > 0.9"
                    },
                    {
                        "field": "severity",
                        "operator": "equals",
                        "value": "HIGH",
                        "action": "warn",
                        "description": "Warn on high vulnerabilities"
                    }
                ],
                enabled=True
            )

            # Create IaC policy
            self.create_policy(
                name="IaC Security Gate",
                description="Policy for Infrastructure as Code scans",
                rules=[
                    {
                        "field": "severity",
                        "operator": "equals",
                        "value": "CRITICAL",
                        "action": "fail",
                        "description": "Fail on critical misconfigurations"
                    },
                    {
                        "field": "severity",
                        "operator": "equals",
                        "value": "HIGH",
                        "action": "fail",
                        "description": "Fail on high misconfigurations"
                    },
                    {
                        "field": "severity",
                        "operator": "equals",
                        "value": "MEDIUM",
                        "action": "warn",
                        "description": "Warn on medium misconfigurations"
                    }
                ],
                enabled=True
            )

            logger.info("Created default security policies")

    def create_policy(
        self,
        name: str,
        description: str,
        rules: List[Dict[str, Any]],
        enabled: bool = True,
        fail_on_warn: bool = False,
        apply_to: Optional[List[str]] = None
    ) -> Policy:
        """Create a new policy"""
        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        policy = Policy(
            id=policy_id,
            name=name,
            description=description,
            enabled=enabled,
            rules=rules,
            created_at=now,
            updated_at=now,
            fail_on_warn=fail_on_warn,
            apply_to=apply_to or []
        )

        # Store in Redis
        get_redis_client().hset(POLICIES_KEY, policy_id, json.dumps(asdict(policy)))

        logger.info(f"Created policy: {name} ({policy_id})")
        return policy

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID"""
        data = get_redis_client().hget(POLICIES_KEY, policy_id)
        if not data:
            return None

        policy_dict = json.loads(data)
        return Policy(**policy_dict)

    def update_policy(
        self,
        policy_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        rules: Optional[List[Dict[str, Any]]] = None,
        enabled: Optional[bool] = None,
        fail_on_warn: Optional[bool] = None,
        apply_to: Optional[List[str]] = None
    ) -> Optional[Policy]:
        """Update an existing policy"""
        policy = self.get_policy(policy_id)
        if not policy:
            return None

        if name is not None:
            policy.name = name
        if description is not None:
            policy.description = description
        if rules is not None:
            policy.rules = rules
        if enabled is not None:
            policy.enabled = enabled
        if fail_on_warn is not None:
            policy.fail_on_warn = fail_on_warn
        if apply_to is not None:
            policy.apply_to = apply_to

        policy.updated_at = datetime.now(timezone.utc).isoformat()

        # Update in Redis
        get_redis_client().hset(POLICIES_KEY, policy_id, json.dumps(asdict(policy)))

        logger.info(f"Updated policy: {policy.name} ({policy_id})")
        return policy

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy"""
        result = get_redis_client().hdel(POLICIES_KEY, policy_id)
        if result:
            logger.info(f"Deleted policy: {policy_id}")
        return result > 0

    def list_policies(self) -> List[Policy]:
        """List all policies"""
        policies = []
        data = get_redis_client().hgetall(POLICIES_KEY)

        for policy_id, policy_json in data.items():
            policy_dict = json.loads(policy_json)
            policies.append(Policy(**policy_dict))

        return policies

    def evaluate_vulnerabilities(
        self,
        policy_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> PolicyEvaluationResult:
        """Evaluate vulnerabilities against a policy"""
        policy = self.get_policy(policy_id)
        if not policy:
            raise ValueError(f"Policy not found: {policy_id}")

        if not policy.enabled:
            return PolicyEvaluationResult(
                policy_id=policy_id,
                policy_name=policy.name,
                passed=True,
                status="skipped",
                violations=[],
                summary={"fail": 0, "warn": 0, "pass": len(vulnerabilities)},
                evaluated_at=datetime.now(timezone.utc).isoformat()
            )

        violations = []
        summary = {"fail": 0, "warn": 0, "pass": 0}

        for rule in policy.rules:
            matched = self._evaluate_rule(rule, vulnerabilities)
            if matched:
                action = rule.get("action", "warn")
                summary[action] = summary.get(action, 0) + len(matched)

                violations.append({
                    "rule": rule,
                    "action": action,
                    "message": rule.get("description", f"Rule {rule['field']} {rule['operator']} {rule['value']}"),
                    "matched_count": len(matched),
                    "matched_items": matched[:10]  # Limit to first 10
                })

        # Determine overall status
        passed = summary["fail"] == 0
        if policy.fail_on_warn and summary["warn"] > 0:
            passed = False

        status = "passed" if passed else "failed"
        if passed and summary["warn"] > 0:
            status = "warning"

        return PolicyEvaluationResult(
            policy_id=policy_id,
            policy_name=policy.name,
            passed=passed,
            status=status,
            violations=violations,
            summary=summary,
            evaluated_at=datetime.now(timezone.utc).isoformat()
        )

    def evaluate_iac_findings(
        self,
        policy_id: str,
        findings: List[Dict[str, Any]]
    ) -> PolicyEvaluationResult:
        """Evaluate IaC findings against a policy"""
        # IaC findings use the same structure, just different field names
        # Map findings to vulnerability-like structure
        mapped_findings = []
        for finding in findings:
            mapped_findings.append({
                "severity": finding.get("severity", "UNKNOWN"),
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "file": finding.get("file", ""),
                "message": finding.get("message", "")
            })

        return self.evaluate_vulnerabilities(policy_id, mapped_findings)

    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        items: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Evaluate a single rule against items, return matched items"""
        field = rule.get("field")
        operator = rule.get("operator")
        value = rule.get("value")

        matched = []

        for item in items:
            item_value = self._get_field_value(item, field)
            if item_value is None:
                continue

            if self._compare(item_value, operator, value):
                matched.append(item)

        return matched

    def _get_field_value(self, item: Dict[str, Any], field: str) -> Any:
        """Get field value from item, supporting nested fields"""
        if "." in field:
            parts = field.split(".")
            value = item
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return None
            return value

        # Handle common field mappings
        field_mappings = {
            "severity": ["severity", "Severity"],
            "epss_score": ["epss_score", "epss.score", "epss"],
            "in_kev": ["in_kev", "kev_match", "is_kev"],
            "cve_id": ["cve_id", "vulnerability", "id", "CVE"],
            "package": ["package", "Package", "artifact.name"],
            "license": ["license", "License", "licenses"]
        }

        for mapping in field_mappings.get(field, [field]):
            if "." in mapping:
                parts = mapping.split(".")
                value = item
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
                if value is not None:
                    return value
            elif mapping in item:
                return item[mapping]

        return item.get(field)

    def _compare(self, item_value: Any, operator: str, rule_value: Any) -> bool:
        """Compare values based on operator"""
        try:
            if operator == "equals":
                if isinstance(item_value, str) and isinstance(rule_value, str):
                    return item_value.upper() == rule_value.upper()
                return item_value == rule_value

            elif operator == "not_equals":
                if isinstance(item_value, str) and isinstance(rule_value, str):
                    return item_value.upper() != rule_value.upper()
                return item_value != rule_value

            elif operator == "greater_than":
                return float(item_value) > float(rule_value)

            elif operator == "less_than":
                return float(item_value) < float(rule_value)

            elif operator == "greater_or_equal":
                return float(item_value) >= float(rule_value)

            elif operator == "less_or_equal":
                return float(item_value) <= float(rule_value)

            elif operator == "contains":
                return str(rule_value).lower() in str(item_value).lower()

            elif operator == "in":
                if isinstance(rule_value, list):
                    return item_value in rule_value
                return str(item_value) in str(rule_value)

            else:
                logger.warning(f"Unknown operator: {operator}")
                return False

        except (ValueError, TypeError) as e:
            logger.debug(f"Comparison failed: {e}")
            return False


# Global policy engine instance
policy_engine = PolicyEngine()
