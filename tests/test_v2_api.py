"""Contract tests for the initial v2 public Python API."""
import base64
import json

import pytest

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


def _token(header=None, claims=None, signature="signature"):
    return ".".join(
        (
            _segment(header if header is not None else {"alg": "HS256", "typ": "JWT"}),
            _segment(claims if claims is not None else {"sub": "test-subject", "exp": 4102444800}),
            signature,
        )
    )


def test_inspection_never_claims_signature_verification():
    token = _token()
    assessment = inspect_token(token)

    assert assessment.verification_status is VerificationStatus.NOT_ATTEMPTED
    assert assessment.to_dict()["verification_status"] == "not_attempted"
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


def test_assessment_rejects_non_mapping_claims():
    with pytest.raises(TypeError):
        Assessment(header={}, claims=[])  # type: ignore[arg-type]
