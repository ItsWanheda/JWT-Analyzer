"""M1 contract tests for schema, stage separation, and deterministic policy results."""

import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path

from jwt_analyzer import (
    ASSESSMENT_SCHEMA_VERSION,
    Assessment,
    AssessmentPolicy,
    Finding,
    Severity,
    VerificationStatus,
    evaluate_policy,
    get_policy_profile,
    inspect_token,
    verify_signature_with_public_key,
    verify_with_public_key,
)


def _segment(value):
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).decode("ascii").rstrip("=")


def _token(header=None, claims=None, signature="c2lnbmF0dXJl"):
    return ".".join(
        (
            _segment(header if header is not None else {"alg": "RS256", "typ": "JWT"}),
            _segment(claims if claims is not None else {"sub": "test", "exp": 4102444800}),
            signature,
        )
    )


def _rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key.decode("ascii")


def test_assessment_schema_json_round_trip_is_stable():
    assessment = inspect_token(_token(claims={"sub": "demo", "exp": 4102444800}))
    first_json = assessment.to_json()
    second_json = assessment.to_json()

    assert first_json == second_json
    restored = Assessment.from_json(first_json)
    assert restored.to_dict() == assessment.to_dict()
    assert restored.schema_version == ASSESSMENT_SCHEMA_VERSION == "1.1"
    assert "token" not in restored.to_dict()
    assert "c2lnbmF0dXJl" not in first_json


def test_assessment_sorts_findings_by_severity_then_stable_id():
    high = Finding(
        id="sample.high",
        title="High",
        description="A high-severity test finding.",
        severity=Severity.HIGH,
    )
    low = Finding(
        id="sample.low",
        title="Low",
        description="A low-severity test finding.",
        severity=Severity.LOW,
    )
    other_high = Finding(
        id="sample.a_high",
        title="Another high",
        description="Another high-severity test finding.",
        severity=Severity.HIGH,
    )
    first = Assessment(
        header={},
        claims={},
        signature_present=True,
        findings=(low, high, other_high),
        assessed_at="2026-01-02T03:04:05Z",
    )
    second = Assessment(
        header={},
        claims={},
        signature_present=True,
        findings=(other_high, low, high),
        assessed_at="2026-01-02T03:04:05Z",
    )

    assert [item.id for item in first.findings] == [
        "sample.a_high",
        "sample.high",
        "sample.low",
    ]
    assert first.to_json() == second.to_json()


def test_assessment_rejects_duplicate_finding_ids_and_unknown_fields():
    finding = Finding(
        id="sample.same",
        title="Same",
        description="Duplicate IDs are ambiguous.",
        severity=Severity.LOW,
    )
    with pytest.raises(ValueError, match="unique"):
        Assessment(header={}, claims={}, signature_present=False, findings=(finding, finding))

    serialized = inspect_token(_token()).to_dict()
    serialized["token"] = "must-not-be-a-field"
    with pytest.raises(ValueError, match="unknown assessment field"):
        Assessment.from_dict(serialized)


def test_assessment_json_rejects_duplicate_keys_and_nonstandard_numbers():
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        Assessment.from_json('{"schema_version":"1.1","schema_version":"1.1"}')
    with pytest.raises(ValueError, match="non-standard JSON numeric constant"):
        Assessment.from_json('{"claims":{"exp":NaN}}')


def test_parsing_keeps_claim_policy_out_of_the_parse_stage():
    assessment = inspect_token(_token(claims={"sub": "demo", "exp": "tomorrow"}))

    assert assessment.verification_status is VerificationStatus.NOT_ATTEMPTED
    assert assessment.claims["exp"] == "tomorrow"
    result = evaluate_policy(
        assessment,
        get_policy_profile("baseline", now_timestamp=1_800_000_000),
    )
    finding_ids = {item.id for item in result.findings}

    assert "jwt.policy.time_claim_invalid.exp" in finding_ids
    assert result.verification_status is VerificationStatus.NOT_ATTEMPTED
    assert result.policy["status"] == "not_verified"
    assert result.policy["compliant"] is None
    assert any("unverified claims" in warning.lower() for warning in result.warnings)


def test_strict_policy_requires_registered_claims_and_narrower_algorithms():
    assessment = inspect_token(
        _token(
            header={"alg": "RS512", "typ": "JWT"},
            claims={"sub": "demo", "exp": 4102444800},
        )
    )
    result = evaluate_policy(
        assessment,
        get_policy_profile("strict", now_timestamp=1_800_000_000),
    )
    ids = {item.id for item in result.findings}

    assert "jwt.policy.algorithm_not_allowed" in ids
    assert "jwt.policy.issuer_missing" in ids
    assert "jwt.policy.audience_missing" in ids
    assert any(item.startswith("jwt.policy.claim_missing.iat.") for item in ids)
    assert result.policy["profile"] == "strict"
    assert result.policy["status"] == "not_verified"


def test_custom_policy_checks_issuer_audience_and_required_claims():
    assessment = inspect_token(
        _token(
            header={"alg": "RS256"},
            claims={"exp": 900, "iss": "https://wrong.example", "aud": "other"},
        )
    )
    policy = AssessmentPolicy(
        name="tenant-production",
        accepted_algorithms=("RS256",),
        required_claims=("exp", "tenant"),
        time_claims=("exp",),
        issuer="https://expected.example",
        audience="orders-api",
        require_issuer=True,
        require_audience=True,
        now_timestamp=1000,
    )
    result = evaluate_policy(assessment, policy)
    ids = {item.id for item in result.findings}

    assert "jwt.policy.token_expired" in ids
    assert "jwt.policy.issuer_mismatch" in ids
    assert "jwt.policy.audience_mismatch" in ids
    assert any(item.startswith("jwt.policy.claim_missing.tenant.") for item in ids)
    assert result.policy["profile"] == "tenant-production"
    assert result.verification_status is VerificationStatus.NOT_ATTEMPTED


def test_signature_verification_does_not_apply_expiry_or_issuer_policy():
    private_key, public_key = _rsa_key_pair()
    token = jwt.encode(
        {"sub": "old-user", "exp": 1, "iss": "https://wrong.example"},
        private_key,
        algorithm="RS256",
    )
    signature_result = verify_signature_with_public_key(
        token,
        public_key,
        algorithms=("RS256",),
    )

    assert signature_result.verification_status is VerificationStatus.VERIFIED
    assert signature_result.policy is None
    assert not signature_result.errors
    policy_result = evaluate_policy(
        signature_result,
        get_policy_profile(
            "baseline",
            issuer="https://expected.example",
            require_issuer=True,
            now_timestamp=1000,
        ),
    )
    ids = {item.id for item in policy_result.findings}

    assert policy_result.verification_status is VerificationStatus.VERIFIED
    assert policy_result.policy["status"] == "failed"
    assert "jwt.policy.token_expired" in ids
    assert "jwt.policy.issuer_mismatch" in ids


def test_combined_verifier_keeps_signature_state_separate_from_policy_state():
    private_key, public_key = _rsa_key_pair()
    token = jwt.encode(
        {
            "sub": "verified-user",
            "exp": 4102444800,
            "iss": "https://actual.example",
        },
        private_key,
        algorithm="RS256",
    )
    result = verify_with_public_key(
        token,
        public_key,
        algorithms=["RS256"],
        issuer="https://expected.example",
    )

    assert result.verification_status is VerificationStatus.VERIFIED
    assert result.policy["status"] == "failed"
    assert "jwt.policy.issuer_mismatch" in {item.id for item in result.findings}


def test_policy_profile_input_validation():
    with pytest.raises(ValueError, match="unknown policy profile"):
        get_policy_profile("production-ish")
    with pytest.raises(ValueError, match="unsupported algorithm"):
        AssessmentPolicy(name="invalid", accepted_algorithms=("none",))
    with pytest.raises(ValueError, match="time_claims"):
        AssessmentPolicy(name="invalid", time_claims=("exp", "custom"))


def test_schema_and_fixture_match_the_public_contract():
    root = Path(__file__).parent
    fixture = json.loads((root / "fixtures" / "assessment-v1.1.json").read_text("utf-8"))
    schema = json.loads(
        (root.parent / "jwt_analyzer" / "assessment-v1.1.schema.json").read_text("utf-8")
    )
    assessment = Assessment.from_dict(fixture)

    assert schema["properties"]["schema_version"]["const"] == ASSESSMENT_SCHEMA_VERSION
    assert set(schema["required"]) == set(assessment.to_dict())
    assert set(schema["properties"]["findings"]["items"]["required"]) == set(
        assessment.findings[0].to_dict()
    )
    assert Assessment.from_json(assessment.to_json()).to_dict() == assessment.to_dict()
