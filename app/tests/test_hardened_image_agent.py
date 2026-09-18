"""
Unit Tests for Hardened Base Image Advisor & App Compatibility Agent
"""
import pytest
from app.hardened_image_agent import (
    HardenedCatalogService,
    StaticDockerfileAnalyzer,
    GitLabProjectFetcher,
    HardenedImageAgent,
    IssueCategory,
    IssueSeverity,
)


def test_resolve_base_spec():
    """Test resolution of hardened base image specs."""
    spec = HardenedCatalogService.resolve_spec("jdk21")
    assert spec.name == "jdk21"
    assert "java" in spec.available_commands
    assert "microdnf" in spec.removed_notable.get("package-manager", [])
    assert spec.fonts_variant == "jdk21-fonts"


def test_resolve_base_spec_from_full_url():
    """Test resolution of spec from full registry pull URL."""
    spec = HardenedCatalogService.resolve_spec("10.0.14.79:5009/tools/hardened-images/python314:latest")
    assert spec.name == "python314"
    assert "python" in spec.available_commands or "python3" in spec.available_commands
    assert "gcc" in spec.removed_notable.get("dev-build", [])


def test_static_analyzer_detects_removed_tools():
    """Test static analyzer catches curl, microdnf, git, and suggests wget."""
    dockerfile = """
    FROM 10.0.14.79:5009/tools/hardened-images/jdk21:latest
    RUN microdnf install -y curl git
    RUN curl -fsSL -o /app/app.jar http://nexus/app.jar
    """
    spec = HardenedCatalogService.resolve_spec("jdk21")
    issues = StaticDockerfileAnalyzer.analyze(dockerfile, spec)

    categories = [i.category for i in issues]
    assert IssueCategory.PACKAGE_MANAGER in categories
    assert IssueCategory.STRIPPED_TOOL in categories
    assert IssueCategory.BUILD_TOOL_IN_RUNTIME in categories

    curl_issue = next(i for i in issues if "curl" in i.title.lower())
    assert "wget" in curl_issue.remediation


def test_static_analyzer_detects_permissions_and_ports():
    """Test static analyzer catches privileged ports and missing --chown."""
    dockerfile = """
    FROM 10.0.14.79:5009/tools/hardened-images/jdk21:latest
    COPY . /app
    EXPOSE 80
    ENTRYPOINT /start.sh
    """
    spec = HardenedCatalogService.resolve_spec("jdk21")
    issues = StaticDockerfileAnalyzer.analyze(dockerfile, spec)

    categories = [i.category for i in issues]
    assert IssueCategory.PERMISSION_DENIED in categories
    assert IssueCategory.PRIVILEGED_PORT in categories
    assert IssueCategory.ENTRYPOINT_CONFLICT in categories


def test_static_analyzer_detects_missing_font_stack():
    """Test that applications using JasperReports or PDFBox are flagged to switch to -fonts."""
    dockerfile = """
    FROM 10.0.14.79:5009/tools/hardened-images/jdk21:latest
    # Application uses jasperreports and pdfbox for PDF rendering
    COPY target/jasperreports-service.jar /app/app.jar
    """
    spec = HardenedCatalogService.resolve_spec("jdk21")
    issues = StaticDockerfileAnalyzer.analyze(dockerfile, spec)

    font_issue = next((i for i in issues if i.category == IssueCategory.MISSING_FONTS), None)
    assert font_issue is not None
    assert "jdk21-fonts" in font_issue.remediation


def test_gitlab_target_parser():
    """Test parsing of GitLab project URLs, branches, and file paths."""
    # Full blob URL
    proj, ref, path = GitLabProjectFetcher.parse_gitlab_target(
        "https://gitlab.sixdee/devops/my-app/-/blob/feature-branch/deploy/Dockerfile"
    )
    assert proj == "devops/my-app"
    assert ref == "feature-branch"
    assert path == "deploy/Dockerfile"

    # Tree URL
    proj, ref, path = GitLabProjectFetcher.parse_gitlab_target(
        "https://gitlab.sixdee/devops/my-app/-/tree/development"
    )
    assert proj == "devops/my-app"
    assert ref == "development"
    assert path is None

    # Plain namespace path
    proj, ref, path = GitLabProjectFetcher.parse_gitlab_target("devops/my-app")
    assert proj == "devops/my-app"
    assert ref is None
    assert path is None


def test_rule_based_remediation_generation():
    """Test rule-based fallback generation produces valid multi-stage Dockerfile."""
    dockerfile = """
    FROM 10.0.14.79:5009/tools/hardened-images/jdk21:latest
    RUN microdnf install -y curl
    """
    spec = HardenedCatalogService.resolve_spec("jdk21")
    issues = StaticDockerfileAnalyzer.analyze(dockerfile, spec)
    remediation = HardenedImageAgent._generate_rule_based_remediation(dockerfile, spec, issues)

    gen_dockerfile = remediation["remediated_dockerfile"]
    assert "AS builder" in gen_dockerfile
    assert f"FROM {spec.pull_url}" in gen_dockerfile
    assert "USER 10001" in gen_dockerfile
    assert "EXPOSE 8080" in gen_dockerfile
    assert "--chown=10001:10001" in gen_dockerfile


def test_calculate_reduction_matrix():
    """Test calculation of CVE and attack surface reduction matrix."""
    spec = HardenedCatalogService.resolve_spec("jdk21")
    matrix = HardenedImageAgent.calculate_reduction_matrix("FROM openjdk:21", spec)

    assert matrix["cve_delta"]["critical"]["reduction_pct"] == 100
    assert matrix["cve_delta"]["high"]["reduction_pct"] == 100
    assert matrix["cve_delta"]["critical"]["after"] == 0
    assert matrix["cve_delta"]["high"]["after"] == 0
    assert matrix["cve_delta"]["total"]["reduction_pct"] > 0
    assert matrix["attack_surface_delta"]["packages"]["before"] > matrix["attack_surface_delta"]["packages"]["after"]
    assert matrix["compliance"]["cis_docker_4_1_non_root"] == "PASS"
    assert matrix["compliance"]["cis_docker_4_3_no_package_manager"] == "PASS"


def test_generate_diff_data():
    """Test generation of aligned side-by-side and unified diff data."""
    original = "FROM openjdk:21\nRUN apt-get install curl\nEXPOSE 80\n"
    remediated = "FROM 10.0.14.79:5009/tools/hardened-images/jdk21:latest\nEXPOSE 8080\nUSER 10001:10001\n"

    diff_data = HardenedImageAgent.generate_diff_data(original, remediated)

    assert "unified_diff" in diff_data
    assert "side_by_side" in diff_data
    assert "stats" in diff_data
    assert diff_data["stats"]["added_lines"] > 0
    assert diff_data["stats"]["removed_lines"] > 0
    assert len(diff_data["side_by_side"]) > 0

