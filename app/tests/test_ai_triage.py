"""
Tests for AI-assisted vulnerability triage module (app.ai_triage).
Verifies Google ADK Agent + LiteLLM integration with internal local Qwen model,
backwards compatibility, schema adherence, error handling, and caching.
"""
import os
import json
import pytest
from unittest.mock import patch, MagicMock
from dataclasses import is_dataclass, asdict

import app.ai_triage as ai_triage
from app.ai_triage import (
    TriageResult,
    is_ai_enabled,
    get_status,
    triage_vulnerability,
    triage_batch,
    generate_remediation_plan,
    explain_finding,
    generate_triage,
    generate_remediation_summary,
    _extract_json,
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
)


import fakeredis


@pytest.fixture(autouse=True)
def mock_redis_for_triage(monkeypatch):
    fake_r = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(ai_triage, "get_redis_client", lambda: fake_r)
    return fake_r


@pytest.fixture
def sample_scan_data():

    return {
        "scan_id": "test-scan-123",
        "image_name": "registry.internal/apps/web:v1.0.0",
        "critical": 2,
        "high": 5,
        "medium": 10,
        "low": 3,
        "fixable_critical": 2,
        "fixable_high": 4,
        "total_packages": 120,
        "base_image_os": "debian",
        "base_image_os_version": "12",
        "total_unique_vulnerabilities": 20,
    }


@pytest.fixture
def sample_vulnerabilities():
    return [
        {
            "id": "CVE-2024-1234",
            "cve_id": "CVE-2024-1234",
            "package": "openssl",
            "version": "3.0.2",
            "fix_version": "3.0.3",
            "severity": "critical",
            "epss_score": 0.95,
            "kev_match": True,
            "description": "Remote code execution in OpenSSL handshake",
        },
        {
            "id": "CVE-2024-5678",
            "cve_id": "CVE-2024-5678",
            "package": "curl",
            "version": "7.88.1",
            "fix_version": "7.88.2",
            "severity": "high",
            "epss_score": 0.62,
            "kev_match": False,
            "description": "Buffer overflow in cookie parsing",
        },
    ]


# ==========================================================================
# 1. Backwards Compatibility & Export Schema Tests
# ==========================================================================

def test_triage_result_dataclass():
    """Ensure TriageResult is a dataclass with expected fields."""
    assert is_dataclass(TriageResult)
    result = TriageResult(
        scan_id="scan-1",
        risk_classification="critical_action",
        executive_summary="Urgent action required.",
        prioritized_actions=[{"action": "Upgrade openssl", "priority": 1}],
        exploit_context="Active in CISA KEV.",
        remediation_effort="minimal",
        generated_at="2026-09-17T12:00:00Z",
        model_used="qwen3.8-27b",
        cached=False,
    )
    d = asdict(result)
    assert d["scan_id"] == "scan-1"
    assert d["risk_classification"] == "critical_action"
    assert d["cached"] is False


def test_status_schema():
    """Verify get_status returns dictionary with required keys."""
    status = get_status()
    assert isinstance(status, dict)
    assert "enabled" in status
    assert "provider" in status
    assert "model" in status
    assert "endpoint" in status
    assert isinstance(status["enabled"], bool)


def test_is_ai_enabled_toggle(monkeypatch):
    """Test AI enabled toggle across various environment configurations."""
    # Disabled explicitly via AI_TRIAGE_ENABLED=false
    monkeypatch.setenv("AI_TRIAGE_ENABLED", "false")
    assert is_ai_enabled() is False

    # Disabled explicitly via AI_TRIAGE_PROVIDER=none
    monkeypatch.setenv("AI_TRIAGE_ENABLED", "true")
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "none")
    assert is_ai_enabled() is False

    # Anthropic without key -> False
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert is_ai_enabled() is False

    # Anthropic with key -> True
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert is_ai_enabled() is True

    # ADK / OpenAI provider enabled with internal model defaults
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")
    monkeypatch.setenv("AI_TRIAGE_BASE_URL", DEFAULT_BASE_URL)
    monkeypatch.setenv("AI_TRIAGE_MODEL", DEFAULT_MODEL)
    assert is_ai_enabled() is True


# ==========================================================================
# 2. JSON & Reasoning Noise Stripping Tests
# ==========================================================================

def test_extract_json_clean():
    """Test extracting clean JSON string."""
    raw = '{"risk_classification": "high_priority"}'
    assert _extract_json(raw) == raw


def test_extract_json_with_think_blocks_and_preamble():
    """Test stripping Qwen <think> reasoning blocks, markdown fences, and conversational preambles."""
    noisy = """<think>
The container has 2 critical vulnerabilities including openssl CVE-2024-1234 in KEV.
Therefore, classification must be critical_action.
</think>
Here is the JSON response:
```json
{
  "risk_classification": "critical_action",
  "executive_summary": "Critical vulnerabilities detected requiring immediate patching."
}
```"""
    extracted = _extract_json(noisy)
    parsed = json.loads(extracted)
    assert parsed["risk_classification"] == "critical_action"
    assert "Critical vulnerabilities" in parsed["executive_summary"]


# ==========================================================================
# 3. Google ADK Agent Integration Tests
# ==========================================================================

def test_generate_triage_adk_success(sample_scan_data, sample_vulnerabilities, monkeypatch):
    """Test generate_triage using Google ADK Agent runner and verify schema."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")
    monkeypatch.setenv("AI_TRIAGE_BASE_URL", "http://10.0.6.31:8000/v1")
    monkeypatch.setenv("AI_TRIAGE_MODEL", "qwen3.8-27b")

    mock_llm_json = json.dumps({
        "risk_classification": "critical_action",
        "executive_summary": "Immediate remediation required for CVE-2024-1234.",
        "prioritized_actions": [
            {
                "priority": 1,
                "action": "Upgrade openssl to 3.0.3",
                "packages": ["openssl"],
                "cves_fixed": ["CVE-2024-1234"],
                "effort": "minimal",
                "impact": "Mitigate active KEV exploit",
            }
        ],
        "exploit_context": "Active exploitation observed in the wild.",
        "remediation_effort": "minimal",
    })

    with patch.object(ai_triage, "_call_llm", return_value=mock_llm_json) as mock_call:
        result = generate_triage(
            scan_id="test-scan-123",
            scan_data=sample_scan_data,
            vulnerabilities=sample_vulnerabilities,
            force=True,
        )

        mock_call.assert_called_once()
        assert result["scan_id"] == "test-scan-123"
        assert result["risk_classification"] == "critical_action"
        assert len(result["prioritized_actions"]) == 1
        assert result["model_used"] == "qwen3.8-27b"
        assert result["provider"] == "adk"
        assert result["enabled"] is True
        assert result["cached"] is False


def test_generate_remediation_summary_success(sample_scan_data, sample_vulnerabilities, monkeypatch):
    """Test generate_remediation_summary generates expected schema."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")

    mock_guide = json.dumps({
        "title": "Remediation Guide for web:v1.0.0",
        "risk_level": "critical",
        "immediate_actions": ["Upgrade openssl"],
        "package_updates": [
            {
                "package": "openssl",
                "current": "3.0.2",
                "target": "3.0.3",
                "cves_fixed": 1,
                "command": "apt-get install --only-upgrade openssl",
            }
        ],
        "base_image_recommendation": "Upgrade to debian:12-slim",
        "estimated_effort": "30 minutes",
        "notes": "Test staging deployment before production release.",
    })

    with patch.object(ai_triage, "_call_llm", return_value=mock_guide):
        result = generate_remediation_summary(
            scan_id="test-scan-123",
            scan_data=sample_scan_data,
            vulnerabilities=sample_vulnerabilities,
        )
        assert result["scan_id"] == "test-scan-123"
        assert result["risk_level"] == "critical"
        assert len(result["package_updates"]) == 1
        assert result["enabled"] is True


def test_generate_remediation_plan_compatibility(sample_scan_data, sample_vulnerabilities, monkeypatch):
    """Verify generate_remediation_plan is fully backwards compatible."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")

    mock_guide = json.dumps({
        "title": "Plan for web:v1.0.0",
        "risk_level": "high",
        "immediate_actions": ["Update packages"],
        "package_updates": [],
        "base_image_recommendation": "None",
        "estimated_effort": "1 hour",
        "notes": "",
    })

    with patch.object(ai_triage, "_call_llm", return_value=mock_guide):
        # Call with positional scan_id, scan_data, vulnerabilities
        res1 = generate_remediation_plan("test-scan-plan-compat-123", sample_scan_data, sample_vulnerabilities)
        assert res1["scan_id"] == "test-scan-plan-compat-123"
        assert res1["risk_level"] == "high"

        # Call with kwargs
        res2 = generate_remediation_plan(scan_id="test-scan-456", scan_data=sample_scan_data)
        assert res2["scan_id"] == "test-scan-456"


# ==========================================================================
# 4. Single Vulnerability & Batch Triage Tests
# ==========================================================================

def test_triage_vulnerability_success(sample_vulnerabilities, monkeypatch):
    """Test triage_vulnerability returns a TriageResult dataclass instance."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")
    vuln = sample_vulnerabilities[0]

    mock_output = json.dumps({
        "risk_classification": "critical_action",
        "executive_summary": "Urgent vulnerability in openssl.",
        "prioritized_actions": [{"priority": 1, "action": "Upgrade openssl"}],
        "exploit_context": "Listed on CISA KEV.",
        "remediation_effort": "minimal",
    })

    with patch.object(ai_triage, "_call_llm", return_value=mock_output):
        res = triage_vulnerability(vuln, context={"scan_id": "test-scan-123"})
        assert isinstance(res, TriageResult)
        assert res.scan_id == "test-scan-123"
        assert res.risk_classification == "critical_action"
        assert res.exploit_context == "Listed on CISA KEV."
        assert res.model_used == "qwen3.8-27b"


def test_triage_batch(sample_vulnerabilities, monkeypatch):
    """Test triage_batch returns a list of TriageResult objects."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")

    mock_output = json.dumps({
        "risk_classification": "high_priority",
        "executive_summary": "Package requires update.",
        "prioritized_actions": [],
        "exploit_context": "",
        "remediation_effort": "moderate",
    })

    with patch.object(ai_triage, "_call_llm", return_value=mock_output):
        results = triage_batch(sample_vulnerabilities, context={"scan_id": "test-batch-1"})
        assert isinstance(results, list)
        assert len(results) == len(sample_vulnerabilities)
        for r in results:
            assert isinstance(r, TriageResult)


def test_explain_finding(sample_vulnerabilities, monkeypatch):
    """Test explain_finding provides structured explanations."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")
    vuln = sample_vulnerabilities[0]

    mock_output = json.dumps({
        "finding_id": "CVE-2024-1234",
        "explanation": "OpenSSL memory corruption during TLS handshake.",
        "attack_vector": "Remote network packet with crafted TLS ClientHello.",
        "business_impact": "Full container compromise and potential lateral movement.",
        "recommended_action": "Upgrade openssl package to version >= 3.0.3.",
        "confidence": "high",
    })

    with patch.object(ai_triage, "_call_llm", return_value=mock_output):
        res = explain_finding(vuln)
        assert res["finding_id"] == "CVE-2024-1234"
        assert res["attack_vector"] == "Remote network packet with crafted TLS ClientHello."
        assert res["confidence"] == "high"
        assert res["enabled"] is True


# ==========================================================================
# 5. Graceful Degradation & Fallback Tests
# ==========================================================================

def test_disabled_ai_graceful_response(sample_scan_data, sample_vulnerabilities, monkeypatch):
    """Test that when AI is disabled, all functions degrade gracefully without error."""
    monkeypatch.setenv("AI_TRIAGE_ENABLED", "false")

    triage = generate_triage("scan-disabled", sample_scan_data, sample_vulnerabilities)
    assert triage["enabled"] is False
    assert "unavailable" in triage["error"].lower()

    remediation = generate_remediation_summary("scan-disabled", sample_scan_data, sample_vulnerabilities)
    assert remediation["enabled"] is False
    assert "unavailable" in remediation["error"].lower()

    single = triage_vulnerability(sample_vulnerabilities[0])
    assert single is None

    batch = triage_batch(sample_vulnerabilities)
    assert batch == []

    explained = explain_finding(sample_vulnerabilities[0])
    assert explained["enabled"] is False


def test_unreachable_model_error_handling(sample_scan_data, sample_vulnerabilities, monkeypatch):
    """Test graceful handling when the backend LLM service is unreachable."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")

    with patch.object(ai_triage, "_call_llm", side_effect=ConnectionError("Failed to connect to 10.0.6.31:8000")):
        triage = generate_triage("scan-conn-err", sample_scan_data, sample_vulnerabilities, force=True)
        assert triage["enabled"] is True
        assert "AI triage failed" in triage["error"]

        single = triage_vulnerability(sample_vulnerabilities[0])
        assert single is None


def test_adk_fallback_to_litellm(monkeypatch):
    """Verify fallback from ADK agent to direct LiteLLM when ADK runner errors."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "adk")

    with patch.object(ai_triage, "_call_adk_agent", side_effect=RuntimeError("ADK session error")), \
         patch.object(ai_triage, "_call_litellm", return_value='{"risk_classification": "monitor"}') as mock_litellm:
        raw = ai_triage._call_llm("test prompt")
        assert raw == '{"risk_classification": "monitor"}'
        mock_litellm.assert_called_once()


def test_litellm_fallback_to_openai(monkeypatch):
    """Verify fallback to direct OpenAI client when LiteLLM errors."""
    monkeypatch.setenv("AI_TRIAGE_PROVIDER", "openai")

    with patch.object(ai_triage, "_call_adk_agent", side_effect=RuntimeError("ADK unavailable")), \
         patch.object(ai_triage, "_call_litellm", side_effect=RuntimeError("LiteLLM unavailable")), \
         patch.object(ai_triage, "_call_openai", return_value='{"risk_classification": "accept_risk"}') as mock_openai:
        raw = ai_triage._call_llm("test prompt")
        assert raw == '{"risk_classification": "accept_risk"}'
        mock_openai.assert_called_once()
