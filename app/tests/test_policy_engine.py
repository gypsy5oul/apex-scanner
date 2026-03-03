"""
Tests for the policy engine: policy CRUD, rule evaluation, and comparison operators.
"""
import pytest
from unittest.mock import patch

from app.policy_engine import PolicyEngine, PolicyAction, RuleOperator, Policy


class TestPolicyCRUD:
    """Tests for policy create/read/update/delete."""

    def test_create_policy(self, mock_redis):
        """Creating a policy should return a Policy with ID."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="Test Policy",
            description="A test policy",
            rules=[{
                "field": "severity",
                "operator": "equals",
                "value": "CRITICAL",
                "action": "fail"
            }]
        )

        assert policy.id is not None
        assert policy.name == "Test Policy"
        assert policy.enabled is True
        assert len(policy.rules) == 1

    def test_get_policy(self, mock_redis):
        """Getting a policy by ID should return the same policy."""
        engine = PolicyEngine()
        created = engine.create_policy(
            name="Retrieve Test",
            description="Test retrieval",
            rules=[]
        )

        retrieved = engine.get_policy(created.id)
        assert retrieved is not None
        assert retrieved.name == "Retrieve Test"
        assert retrieved.id == created.id

    def test_get_nonexistent_policy(self, mock_redis):
        """Getting a non-existent policy should return None."""
        engine = PolicyEngine()
        assert engine.get_policy("nonexistent-id") is None

    def test_update_policy(self, mock_redis):
        """Updating a policy should change its fields."""
        engine = PolicyEngine()
        created = engine.create_policy(
            name="Original",
            description="Original description",
            rules=[]
        )

        updated = engine.update_policy(created.id, name="Updated", enabled=False)
        assert updated.name == "Updated"
        assert updated.enabled is False
        assert updated.updated_at != created.created_at

    def test_update_nonexistent(self, mock_redis):
        """Updating a non-existent policy should return None."""
        engine = PolicyEngine()
        assert engine.update_policy("nonexistent-id", name="New") is None

    def test_delete_policy(self, mock_redis):
        """Deleting a policy should remove it."""
        engine = PolicyEngine()
        created = engine.create_policy(
            name="Delete Me",
            description="Will be deleted",
            rules=[]
        )

        assert engine.delete_policy(created.id) is True
        assert engine.get_policy(created.id) is None

    def test_delete_nonexistent(self, mock_redis):
        """Deleting non-existent policy should return False."""
        engine = PolicyEngine()
        assert engine.delete_policy("nonexistent-id") is False

    def test_list_policies(self, mock_redis):
        """Listing should return all created policies."""
        engine = PolicyEngine()
        # Default policies are created in __init__
        policies = engine.list_policies()

        # Should have 3 default policies
        assert len(policies) >= 3
        names = [p.name for p in policies]
        assert "Production Security Gate" in names
        assert "Development Security Gate" in names
        assert "IaC Security Gate" in names


class TestPolicyEvaluation:
    """Tests for vulnerability evaluation against policies."""

    def test_evaluate_disabled_policy(self, mock_redis):
        """Disabled policies should skip evaluation and pass."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="Disabled",
            description="Disabled policy",
            rules=[{"field": "severity", "operator": "equals", "value": "CRITICAL", "action": "fail"}],
            enabled=False
        )

        vulns = [{"severity": "CRITICAL", "id": "CVE-2024-1234"}]
        result = engine.evaluate_vulnerabilities(policy.id, vulns)

        assert result.passed is True
        assert result.status == "skipped"

    def test_evaluate_fail_on_critical(self, mock_redis):
        """Critical vulns should fail a policy with critical-fail rule."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="Strict",
            description="Fails on critical",
            rules=[{"field": "severity", "operator": "equals", "value": "CRITICAL", "action": "fail"}]
        )

        vulns = [
            {"severity": "CRITICAL", "id": "CVE-2024-1111"},
            {"severity": "LOW", "id": "CVE-2024-2222"},
        ]
        result = engine.evaluate_vulnerabilities(policy.id, vulns)

        assert result.passed is False
        assert result.status == "failed"
        assert result.summary["fail"] >= 1

    def test_evaluate_warning(self, mock_redis):
        """Warnings without fails should pass with warning status."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="Warning",
            description="Warns on medium",
            rules=[{"field": "severity", "operator": "equals", "value": "MEDIUM", "action": "warn"}]
        )

        vulns = [{"severity": "MEDIUM", "id": "CVE-2024-3333"}]
        result = engine.evaluate_vulnerabilities(policy.id, vulns)

        assert result.passed is True
        assert result.status == "warning"
        assert result.summary["warn"] >= 1

    def test_evaluate_fail_on_warn(self, mock_redis):
        """With fail_on_warn=True, warnings should cause failure."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="Strict Warnings",
            description="Fails on warnings too",
            rules=[{"field": "severity", "operator": "equals", "value": "MEDIUM", "action": "warn"}],
            fail_on_warn=True
        )

        vulns = [{"severity": "MEDIUM", "id": "CVE-2024-4444"}]
        result = engine.evaluate_vulnerabilities(policy.id, vulns)

        assert result.passed is False

    def test_evaluate_pass_clean_scan(self, mock_redis):
        """Clean scan with no matching rules should pass."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="Clean",
            description="Only fails on critical",
            rules=[{"field": "severity", "operator": "equals", "value": "CRITICAL", "action": "fail"}]
        )

        vulns = [{"severity": "LOW", "id": "CVE-2024-5555"}]
        result = engine.evaluate_vulnerabilities(policy.id, vulns)

        assert result.passed is True
        assert result.status == "passed"
        assert result.summary["fail"] == 0

    def test_evaluate_nonexistent_policy(self, mock_redis):
        """Evaluating against non-existent policy should raise ValueError."""
        engine = PolicyEngine()

        with pytest.raises(ValueError, match="Policy not found"):
            engine.evaluate_vulnerabilities("nonexistent-id", [])

    def test_evaluate_epss_rule(self, mock_redis):
        """EPSS score greater_than rule should match."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="EPSS Gate",
            description="Fails on high EPSS",
            rules=[{"field": "epss_score", "operator": "greater_than", "value": 0.7, "action": "fail"}]
        )

        vulns = [
            {"id": "CVE-1", "epss_score": 0.85},
            {"id": "CVE-2", "epss_score": 0.3},
        ]
        result = engine.evaluate_vulnerabilities(policy.id, vulns)

        assert result.passed is False
        assert result.summary["fail"] == 1

    def test_evaluate_kev_rule(self, mock_redis):
        """KEV rule should match vulnerabilities with in_kev=True."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="KEV Gate",
            description="Fails on KEV",
            rules=[{"field": "in_kev", "operator": "equals", "value": True, "action": "fail"}]
        )

        vulns = [
            {"id": "CVE-1", "in_kev": True},
            {"id": "CVE-2", "in_kev": False},
        ]
        result = engine.evaluate_vulnerabilities(policy.id, vulns)

        assert result.passed is False
        assert result.summary["fail"] == 1

    def test_violations_limited_to_10(self, mock_redis):
        """Matched items in violations should be limited to 10."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="Limit Test",
            description="Tests violation limit",
            rules=[{"field": "severity", "operator": "equals", "value": "HIGH", "action": "fail"}]
        )

        vulns = [{"severity": "HIGH", "id": f"CVE-{i}"} for i in range(20)]
        result = engine.evaluate_vulnerabilities(policy.id, vulns)

        # Each violation entry should have at most 10 matched items
        for violation in result.violations:
            assert len(violation["matched_items"]) <= 10


class TestIaCEvaluation:
    """Tests for IaC findings evaluation."""

    def test_evaluate_iac_findings(self, mock_redis):
        """IaC findings should be evaluated through the same policy engine."""
        engine = PolicyEngine()
        policy = engine.create_policy(
            name="IaC Policy",
            description="Test IaC",
            rules=[{"field": "severity", "operator": "equals", "value": "CRITICAL", "action": "fail"}]
        )

        findings = [
            {"severity": "CRITICAL", "id": "TRIVY-001", "title": "Root user", "file": "Dockerfile"},
            {"severity": "LOW", "id": "TRIVY-002", "title": "No healthcheck", "file": "Dockerfile"},
        ]
        result = engine.evaluate_iac_findings(policy.id, findings)

        assert result.passed is False
        assert result.summary["fail"] >= 1


class TestComparisonOperators:
    """Tests for the _compare method with all operator types."""

    def setup_method(self, method):
        """Create a fresh engine for each test."""
        # Defer patching to within method to avoid issues
        pass

    def _make_engine(self, mock_redis):
        return PolicyEngine()

    def test_equals_string_case_insensitive(self, mock_redis):
        """String equals should be case-insensitive."""
        engine = self._make_engine(mock_redis)
        assert engine._compare("CRITICAL", "equals", "critical") is True
        assert engine._compare("High", "equals", "HIGH") is True

    def test_equals_non_string(self, mock_redis):
        """Non-string equals should use standard comparison."""
        engine = self._make_engine(mock_redis)
        assert engine._compare(True, "equals", True) is True
        assert engine._compare(42, "equals", 42) is True
        assert engine._compare(True, "equals", False) is False

    def test_not_equals(self, mock_redis):
        """not_equals should be the inverse of equals."""
        engine = self._make_engine(mock_redis)
        assert engine._compare("HIGH", "not_equals", "LOW") is True
        assert engine._compare("HIGH", "not_equals", "high") is False

    def test_greater_than(self, mock_redis):
        """greater_than should compare numeric values."""
        engine = self._make_engine(mock_redis)
        assert engine._compare(0.8, "greater_than", 0.7) is True
        assert engine._compare(0.5, "greater_than", 0.7) is False
        assert engine._compare(0.7, "greater_than", 0.7) is False

    def test_less_than(self, mock_redis):
        """less_than should compare numeric values."""
        engine = self._make_engine(mock_redis)
        assert engine._compare(0.3, "less_than", 0.5) is True
        assert engine._compare(0.5, "less_than", 0.3) is False

    def test_greater_or_equal(self, mock_redis):
        """greater_or_equal should include boundary."""
        engine = self._make_engine(mock_redis)
        assert engine._compare(0.7, "greater_or_equal", 0.7) is True
        assert engine._compare(0.8, "greater_or_equal", 0.7) is True
        assert engine._compare(0.6, "greater_or_equal", 0.7) is False

    def test_less_or_equal(self, mock_redis):
        """less_or_equal should include boundary."""
        engine = self._make_engine(mock_redis)
        assert engine._compare(0.7, "less_or_equal", 0.7) is True
        assert engine._compare(0.6, "less_or_equal", 0.7) is True
        assert engine._compare(0.8, "less_or_equal", 0.7) is False

    def test_contains(self, mock_redis):
        """contains should check substring presence."""
        engine = self._make_engine(mock_redis)
        assert engine._compare("Apache Log4j", "contains", "log4j") is True
        assert engine._compare("openssl", "contains", "curl") is False

    def test_in_operator_list(self, mock_redis):
        """in operator should check membership in a list."""
        engine = self._make_engine(mock_redis)
        assert engine._compare("CRITICAL", "in", ["CRITICAL", "HIGH"]) is True
        assert engine._compare("LOW", "in", ["CRITICAL", "HIGH"]) is False

    def test_unknown_operator(self, mock_redis):
        """Unknown operator should return False."""
        engine = self._make_engine(mock_redis)
        assert engine._compare("value", "unknown_op", "other") is False

    def test_comparison_type_error(self, mock_redis):
        """Type errors in comparison should return False, not raise."""
        engine = self._make_engine(mock_redis)
        # String vs float comparison for greater_than
        assert engine._compare("not-a-number", "greater_than", 0.5) is False


class TestFieldExtraction:
    """Tests for the _get_field_value method."""

    def test_nested_field(self, mock_redis):
        """Dot-notation fields should traverse nested dicts."""
        engine = PolicyEngine()
        item = {"epss": {"score": 0.85}}
        assert engine._get_field_value(item, "epss.score") == 0.85

    def test_field_mapping(self, mock_redis):
        """Common field mappings should resolve alternate names."""
        engine = PolicyEngine()

        # "severity" mapping should find "Severity" key too
        item = {"Severity": "HIGH"}
        assert engine._get_field_value(item, "severity") == "HIGH"

    def test_direct_field(self, mock_redis):
        """Direct field name should be returned."""
        engine = PolicyEngine()
        item = {"custom_field": "value"}
        assert engine._get_field_value(item, "custom_field") == "value"

    def test_missing_field(self, mock_redis):
        """Missing field should return None."""
        engine = PolicyEngine()
        item = {"other": "value"}
        assert engine._get_field_value(item, "nonexistent") is None

    def test_nested_field_missing_intermediate(self, mock_redis):
        """Missing intermediate key in nested path should return None."""
        engine = PolicyEngine()
        item = {"top": "not a dict"}
        assert engine._get_field_value(item, "top.nested.deep") is None


class TestEnumValues:
    """Tests for enum correctness."""

    def test_policy_actions(self):
        """PolicyAction should have fail, warn, pass."""
        assert PolicyAction.FAIL == "fail"
        assert PolicyAction.WARN == "warn"
        assert PolicyAction.PASS == "pass"

    def test_rule_operators(self):
        """RuleOperator should have all comparison types."""
        assert RuleOperator.EQUALS == "equals"
        assert RuleOperator.NOT_EQUALS == "not_equals"
        assert RuleOperator.GREATER_THAN == "greater_than"
        assert RuleOperator.LESS_THAN == "less_than"
        assert RuleOperator.CONTAINS == "contains"
        assert RuleOperator.IN == "in"
