"""Contract tests for the initial v2 public Python API."""
import base64
import json

import pytest
from click.testing import CliRunner

from main import cli
from utils.report import redact_sensitive_data
from jwt_analyzer import (
    Assessment,
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
    inspect_token,
)


def _segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _token(header=None, claims=None, signature="c2lnbmF0dXJl"):
    return ".".join(
        (
            _segment(header if header is not None else {"alg": "HS256", "typ": "JWT"}),
            _segment(claims if claims is not None else {"sub": "test-subject", "exp": 4102444800}),
            signature,
        )
    )



def test_redactor_preserves_finding_text_and_redacts_jwt_values():
    description = (
        "The token header declares alg=none. This confirms the header value; it does not "
        "establish that any server accepts unsigned tokens or is vulnerable to a bypass."
    )
    compact = _token(header={"alg": "HS256"}, claims={"sub": "redaction-test"})
    result = redact_sensitive_data({"diagnostic": description, "example": compact})

    assert result["diagnostic"] == description
    assert result["example"] == "[REDACTED: JWT-like value]"



def test_inspection_never_claims_signature_verification():
    token = _token()
    assessment = inspect_token(token)

    assert assessment.verification_status is VerificationStatus.NOT_ATTEMPTED
    assert assessment.signature_present is True
    assert assessment.to_dict()["verification_status"] == "not_attempted"
    assert assessment.to_dict()["signature_present"] is True
    assert any("untrusted" in warning.lower() for warning in assessment.warnings)
    assert "token" not in assessment.to_dict()


def test_none_algorithm_is_an_indicator_not_a_confirmed_bypass():
    assessment = inspect_token(
        _token(header={"alg": "none", "typ": "JWT"}, claims={"sub": "test"}, signature="")
    )

    finding = next(item for item in assessment.findings if item.id == "jwt.algorithm.none_declared")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.HIGH
    assert "does not" in finding.description.lower()
    assert "vulnerable" in finding.description.lower()
    assert finding.evidence["signature_present"] is False


def test_missing_expiry_is_reported_without_claiming_server_acceptance():
    assessment = inspect_token(_token(claims={"sub": "test-subject"}))
    finding = next(item for item in assessment.findings if item.id == "jwt.claim.exp_missing")

    assert finding.severity is Severity.MEDIUM
    assert "verifier" in finding.description.lower()



def test_suspicious_kid_is_only_a_low_confidence_indicator():
    assessment = inspect_token(_token(header={"alg": "HS256", "kid": "../../etc/passwd"}))
    finding = next(
        item
        for item in assessment.findings
        if item.id == "jwt.header.kid_suspicious_indicator"
    )

    assert finding.severity is Severity.LOW
    assert finding.confidence is Confidence.LOW
    assert "does not prove" in finding.description.lower()


def test_malformed_token_is_rejected():
    with pytest.raises(ValueError):
        inspect_token("not-a-jwt")


def test_finding_serializes_enums_and_rejects_empty_id():
    finding = Finding(
        id="example.finding",
        title="Example",
        description="An observed indicator.",
        severity="low",
        confidence="medium",
    )
    assert finding.to_dict()["severity"] == "low"
    assert finding.to_dict()["confidence"] == "medium"
    with pytest.raises(ValueError):
        Finding(id="", title="Example", description="Bad", severity=Severity.LOW)



def test_cli_reports_alg_none_as_medium_indicator_not_confirmed_bypass(tmp_path):
    token_path = tmp_path / "unsigned.jwt"
    token_path.write_text(
        _token(
            header={"alg": "none", "typ": "JWT"},
            claims={"sub": "test-subject"},
            signature="",
        ),
        encoding="utf-8",
    )
    output = tmp_path / "assessment"
    result = CliRunner().invoke(
        cli,
        [
            "audit",
            "--token-file",
            str(token_path),
            "--skip-bruteforce",
            "--output",
            str(output),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "assessment.json").read_text(encoding="utf-8"))
    finding = next(item for item in report["findings"] if item["type"] == "none_algorithm_indicator")
    assert finding["severity"] == "MEDIUM"
    assert "does not establish" in finding["description"]


def test_cli_does_not_treat_exp_zero_as_a_missing_claim(tmp_path):
    token_path = tmp_path / "expired.jwt"
    token_path.write_text(
        _token(claims={"sub": "test-subject", "exp": 0}),
        encoding="utf-8",
    )
    output = tmp_path / "assessment"
    result = CliRunner().invoke(
        cli,
        [
            "audit",
            "--token-file",
            str(token_path),
            "--skip-bruteforce",
            "--output",
            str(output),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "assessment.json").read_text(encoding="utf-8"))
    assert not any(item["type"] == "no_expiry" for item in report["findings"])


def test_assessment_rejects_non_mapping_claims():
    with pytest.raises(TypeError):
        Assessment(header={}, claims=[], signature_present=True)  # type: ignore[arg-type]
