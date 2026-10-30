"""M2 tests that enforce calibrated severity, confidence and limitation semantics."""

import base64
import json

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from jwt_analyzer import (
    Confidence,
    Severity,
    VerificationStatus,
    evaluate_policy,
    get_policy_profile,
    inspect_token,
    verify_signature_with_public_key,
)


def _segment(value):
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )


def _token(header, claims, signature="c2lnbmF0dXJl"):
    return ".".join((_segment(header), _segment(claims), signature))


def test_inspection_rules_report_confirmed_local_facts_not_remote_vulnerabilities():
    assessment = inspect_token(
        _token(
            {"alg": "none", "kid": "../../etc/passwd"},
            {"sub": "calibration"},
            signature="",
        )
    )
    by_id = {finding.id: finding for finding in assessment.findings}
    none_finding = by_id["jwt.algorithm.none_declared"]
    kid_finding = by_id["jwt.header.kid_suspicious_indicator"]

    assert none_finding.severity is Severity.MEDIUM
    assert none_finding.confidence is Confidence.HIGH
    assert none_finding.stage == "inspection"
    assert none_finding.evidence["algorithm"] == "none"
    assert "does not prove" in none_finding.limitations.lower()
    assert kid_finding.severity is Severity.LOW
    assert kid_finding.confidence is Confidence.LOW
    assert "does not prove" in kid_finding.limitations.lower()


def test_missing_expiry_is_high_confidence_about_presence_not_acceptance():
    assessment = inspect_token(_token({"alg": "RS256"}, {"sub": "no-exp"}))
    finding = next(item for item in assessment.findings if item.id == "jwt.claim.exp_missing")

    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.HIGH
    assert finding.evidence == {"claim": "exp", "present": False}
    assert "untrusted" in finding.limitations.lower()
    assert "verifier" in finding.description.lower()


def test_unverified_policy_findings_keep_conditional_confidence_and_limits():
    assessment = inspect_token(
        _token({"alg": "HS256"}, {"sub": "unverified", "exp": 4_102_444_800})
    )
    result = evaluate_policy(
        assessment,
        get_policy_profile("baseline", now_timestamp=1_800_000_000),
    )
    finding = next(item for item in result.findings if item.id == "jwt.policy.algorithm_not_allowed")

    assert result.verification_status is VerificationStatus.NOT_ATTEMPTED
    assert result.policy["status"] == "not_verified"
    assert result.policy["compliant"] is None
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert "not passed cryptographic verification" in finding.limitations.lower()


def test_verified_policy_mismatch_has_reproducible_local_evidence_and_limits():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    token = jwt.encode(
        {
            "sub": "verified",
            "exp": 4_102_444_800,
            "iss": "https://actual.example",
        },
        private,
        algorithm="RS256",
    )
    signature = verify_signature_with_public_key(
        token,
        public_pem,
        algorithms=("RS256",),
    )
    result = evaluate_policy(
        signature,
        get_policy_profile(
            "baseline",
            issuer="https://expected.example",
            require_issuer=True,
            now_timestamp=1_800_000_000,
        ),
    )
    finding = next(item for item in result.findings if item.id == "jwt.policy.issuer_mismatch")

    assert result.verification_status is VerificationStatus.VERIFIED
    assert result.policy["status"] == "failed"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert finding.evidence["claim"] == "iss"
    assert "does not replace application authorization" in finding.limitations.lower()


def test_all_generated_findings_include_observation_evidence_and_limitations():
    assessment = inspect_token(
        _token(
            {"alg": "none", "kid": "' OR 1=1 --"},
            {"sub": "semantic-check"},
            signature="",
        )
    )

    assert assessment.findings
    assert len({item.id for item in assessment.findings}) == len(assessment.findings)
    for finding in assessment.findings:
        assert finding.id
        assert finding.observation
        assert finding.impact
        assert finding.evidence
        assert finding.limitations
        assert finding.recommendation
