"""Regression tests for M4 reporting formats, schemas, redaction, and CI gates."""

import json

from click.testing import CliRunner

from jwt_analyzer import (
    Assessment,
    Confidence,
    Finding,
    ReportFormat,
    Severity,
    render_report,
    threshold_exceeded,
    validate_json_report,
    validate_sarif_report,
)
from jwt_analyzer.cli_v2 import cli
from jwt_analyzer.config import load_config


def _assessment(severities=None):
    selected = severities or (Severity.MEDIUM, Severity.INFO)
    findings = tuple(
        Finding(
            id=f"jwt/test-{index}",
            title=f"Finding {index}",
            description=f"Description {index}",
            severity=severity,
            confidence=Confidence.HIGH,
            recommendation="Rotate exposed credentials.",
            evidence={"matched_text": "person@example.test", "source": "claim"},
        )
        for index, severity in enumerate(selected)
    )
    return Assessment(
        header={"alg": "HS256", "typ": "JWT"},
        claims={"sub": "sample-user", "email": "person@example.test"},
        signature_present=True,
        findings=findings,
    )


def test_json_report_schema_and_metadata_are_stable():
    assessment = _assessment()
    first = render_report(assessment, ReportFormat.JSON)
    second = render_report(assessment, "json")
    first_data = json.loads(first)
    second_data = json.loads(second)
    validate_json_report(first_data)
    assert first_data == second_data
    assert first_data["report_schema_version"] == "1.0"
    assert first_data["tool"]["name"] == "JWT Analyzer"
    assert first_data["redaction_applied"] is True
    assert "person@example.test" not in first


def test_sarif_report_validates_and_preserves_severity_semantics():
    assessment = _assessment(
        (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    )
    data = json.loads(render_report(assessment, "sarif"))
    validate_sarif_report(data)
    run = data["runs"][0]
    assert [item["level"] for item in run["results"]] == [
        "error",
        "error",
        "warning",
        "note",
        "note",
    ]
    assert [item["ruleId"] for item in run["results"]] == [
        item.id for item in assessment.findings
    ]
    assert run["properties"]["redactionApplied"] is True
    assert "person@example.test" not in json.dumps(data)


def test_html_renderer_escapes_untrusted_text_and_redacts_pii():
    assessment = Assessment(
        header={"alg": "HS256"},
        claims={"email": "person@example.test"},
        signature_present=True,
        findings=(
            Finding(
                id="html/xss",
                title="<script>alert('x')</script>",
                description="Unicode proof: آزمون — 漢字",
                severity=Severity.HIGH,
            ),
        ),
    )
    html_text = render_report(assessment, "html")
    assert "<script>" not in html_text
    assert "&lt;script&gt;" in html_text
    assert "آزمون — 漢字" in html_text
    assert "person@example.test" not in html_text


def test_sensitive_export_requires_explicit_opt_in():
    assessment = _assessment()
    safe = render_report(assessment, "json")
    sensitive = render_report(assessment, "json", include_sensitive=True)
    assert "person@example.test" not in safe
    assert "person@example.test" in sensitive
    assert json.loads(sensitive)["redaction_applied"] is False


def test_threshold_default_and_each_explicit_boundary():
    assessment = _assessment((Severity.INFO, Severity.MEDIUM))
    assert threshold_exceeded(assessment, "high") is False
    assert threshold_exceeded(assessment, "medium") is True
    assert threshold_exceeded(assessment, "info") is True
    assert threshold_exceeded(assessment, "none") is False
    assert threshold_exceeded(_assessment((Severity.CRITICAL,)), "critical") is True


def test_threshold_config_file_and_environment_precedence(tmp_path):
    config_path = tmp_path / "jwt-analyzer.yaml"
    config_path.write_text("fail_on_severity: medium\n", encoding="utf-8")
    config = load_config(
        config_path,
        environ={"JWT_ANALYZER_FAIL_ON_SEVERITY": "critical"},
    )
    assert config.fail_on_severity == "critical"


def test_report_cli_writes_sarif_and_returns_threshold_exit_code(tmp_path):
    assessment = _assessment((Severity.HIGH,))
    source = tmp_path / "assessment.json"
    target = tmp_path / "report.sarif"
    source.write_text(
        json.dumps({"schema_version": "1", "status": "ok", "assessment": assessment.to_dict()}),
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cli,
        [
            "report",
            "--assessment-file",
            str(source),
            "--format",
            "sarif",
            "--output",
            str(target),
            "--fail-on",
            "high",
        ],
    )
    assert result.exit_code == 1
    report = json.loads(target.read_text(encoding="utf-8"))
    validate_sarif_report(report)
    assert "person@example.test" not in target.read_text(encoding="utf-8")


def test_report_cli_defaults_to_redacted_json_on_stdout(tmp_path):
    assessment = _assessment()
    source = tmp_path / "assessment.json"
    source.write_text(json.dumps(assessment.to_dict()), encoding="utf-8")
    result = CliRunner().invoke(
        cli, ["report", "--assessment-file", str(source), "--fail-on", "none"]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    validate_json_report(data)
    assert "person@example.test" not in result.stdout


def test_report_cli_rejects_duplicate_json_keys(tmp_path):
    source = tmp_path / "duplicate.json"
    source.write_text('{"schema_version":"1","schema_version":"2"}', encoding="utf-8")
    result = CliRunner().invoke(cli, ["report", "--assessment-file", str(source)])
    assert result.exit_code == 2
    error = json.loads(result.output)
    assert error["error"]["code"] == "invalid_assessment"
