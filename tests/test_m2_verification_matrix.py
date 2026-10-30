"""M2 cryptographic verification matrix for RSA, ECDSA, EdDSA and HMAC."""

import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from core.async_security import brute_force_parallel
from jwt_analyzer import (
    VerificationStatus,
    evaluate_policy,
    get_policy_profile,
    verify_signature_with_public_key,
)


def _make_key(kind):
    if kind == "RSA":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        algorithm = "RS256"
        algorithm_class = jwt.algorithms.RSAAlgorithm
    elif kind == "EC":
        private = ec.generate_private_key(ec.SECP256R1())
        algorithm = "ES256"
        algorithm_class = jwt.algorithms.ECAlgorithm
    else:
        private = ed25519.Ed25519PrivateKey.generate()
        algorithm = "EdDSA"
        algorithm_class = jwt.algorithms.OKPAlgorithm
    return private, algorithm, algorithm_class


def _public_key_content(private, algorithm_class, fmt):
    public = private.public_key()
    if fmt == "pem":
        return public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    return json.dumps(algorithm_class.to_jwk(public, as_dict=True))


@pytest.mark.parametrize("kind", ["RSA", "EC", "OKP"])
@pytest.mark.parametrize("fmt", ["pem", "jwk"])
def test_signature_verification_matrix_accepts_supported_asymmetric_keys(kind, fmt):
    private, algorithm, algorithm_class = _make_key(kind)
    key_content = _public_key_content(private, algorithm_class, fmt)
    token = jwt.encode(
        {"sub": f"{kind.lower()}-test", "exp": 1},
        private,
        algorithm=algorithm,
    )

    result = verify_signature_with_public_key(
        token,
        key_content,
        algorithms=(algorithm,),
    )

    assert result.verification_status is VerificationStatus.VERIFIED
    assert result.claims["sub"] == f"{kind.lower()}-test"
    assert result.policy is None


@pytest.mark.parametrize(
    ("token_kind", "wrong_key_kind"),
    [
        ("RSA", "EC"),
        ("EC", "RSA"),
        ("OKP", "RSA"),
    ],
)
def test_signature_verification_rejects_algorithm_key_type_mismatch(
    token_kind,
    wrong_key_kind,
):
    private, algorithm, _ = _make_key(token_kind)
    wrong_private, _, wrong_algorithm_class = _make_key(wrong_key_kind)
    token = jwt.encode({"sub": "mismatch"}, private, algorithm=algorithm)
    wrong_public = _public_key_content(wrong_private, wrong_algorithm_class, "pem")

    result = verify_signature_with_public_key(
        token,
        wrong_public,
        algorithms=(algorithm,),
    )

    assert result.verification_status in {
        VerificationStatus.INVALID,
        VerificationStatus.ERROR,
    }
    assert result.verification["verified"] is False
    assert result.errors


def test_signature_verification_rejects_algorithm_outside_explicit_allowlist():
    private, algorithm, algorithm_class = _make_key("RSA")
    token = jwt.encode({"sub": "allowlist"}, private, algorithm=algorithm)
    pem = _public_key_content(private, algorithm_class, "pem")

    result = verify_signature_with_public_key(token, pem, algorithms=("RS512",))

    assert result.verification_status is VerificationStatus.INVALID
    assert result.errors


@pytest.mark.parametrize(
    "key_content",
    [
        "not a public key",
        "-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----",
        '{"kty":"RSA","n":"AQAB","n":"AQAB","e":"AQAB"}',
        '{"kty":"RSA","n":1e9999,"e":"AQAB"}',
    ],
)
def test_public_key_loader_rejects_malformed_or_ambiguous_key_material(key_content):
    result = verify_signature_with_public_key(
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln",
        key_content,
        algorithms=("RS256",),
    )

    assert result.verification_status is VerificationStatus.ERROR
    assert result.errors


def test_public_jwk_must_be_usable_for_signature_verification():
    private, algorithm, algorithm_class = _make_key("RSA")
    token = jwt.encode({"sub": "key-ops"}, private, algorithm=algorithm)
    jwk = algorithm_class.to_jwk(private.public_key(), as_dict=True)
    jwk["use"] = "enc"

    result = verify_signature_with_public_key(
        token,
        json.dumps(jwk),
        algorithms=(algorithm,),
    )

    assert result.verification_status is VerificationStatus.ERROR
    assert result.errors


def test_public_jwk_key_ops_must_allow_verify_and_be_unique():
    private, algorithm, algorithm_class = _make_key("RSA")
    token = jwt.encode({"sub": "key-ops"}, private, algorithm=algorithm)
    jwk = algorithm_class.to_jwk(private.public_key(), as_dict=True)
    jwk["key_ops"] = ["verify", "verify"]

    result = verify_signature_with_public_key(
        token,
        json.dumps(jwk),
        algorithms=(algorithm,),
    )

    assert result.verification_status is VerificationStatus.ERROR
    assert result.errors


def test_public_jwk_declared_algorithm_must_match_token_algorithm():
    private, algorithm, algorithm_class = _make_key("RSA")
    token = jwt.encode({"sub": "jwk-alg"}, private, algorithm=algorithm)
    jwk = algorithm_class.to_jwk(private.public_key(), as_dict=True)
    jwk["alg"] = "RS512"

    result = verify_signature_with_public_key(
        token,
        json.dumps(jwk),
        algorithms=(algorithm,),
    )

    assert result.verification_status is VerificationStatus.INVALID
    assert result.errors


def test_signature_result_is_independent_of_expiry_and_policy_claims():
    private, algorithm, algorithm_class = _make_key("RSA")
    key_content = _public_key_content(private, algorithm_class, "pem")
    token = jwt.encode(
        {
            "sub": "expired-user",
            "exp": 1,
            "nbf": 2000,
            "iss": "https://wrong.example",
            "aud": "wrong-service",
        },
        private,
        algorithm=algorithm,
    )

    signature = verify_signature_with_public_key(
        token,
        key_content,
        algorithms=(algorithm,),
    )
    policy = evaluate_policy(
        signature,
        get_policy_profile(
            "baseline",
            issuer="https://expected.example",
            audience="orders-api",
            require_issuer=True,
            require_audience=True,
            now_timestamp=1000,
        ),
    )
    finding_ids = {finding.id for finding in policy.findings}

    assert signature.verification_status is VerificationStatus.VERIFIED
    assert signature.policy is None
    assert policy.verification_status is VerificationStatus.VERIFIED
    assert policy.policy["status"] == "failed"
    assert "jwt.policy.token_expired" in finding_ids
    assert "jwt.policy.token_not_yet_valid" in finding_ids
    assert "jwt.policy.issuer_mismatch" in finding_ids
    assert "jwt.policy.audience_mismatch" in finding_ids


def test_policy_leeway_is_applied_to_expiry_boundary():
    private, algorithm, algorithm_class = _make_key("RSA")
    token = jwt.encode({"sub": "leeway-user", "exp": 950}, private, algorithm=algorithm)
    signature = verify_signature_with_public_key(
        token,
        _public_key_content(private, algorithm_class, "pem"),
        algorithms=(algorithm,),
    )
    accepted = evaluate_policy(
        signature,
        get_policy_profile("baseline", leeway_seconds=100, now_timestamp=1000),
    )

    assert accepted.policy["status"] == "passed"
    assert not any(item.id == "jwt.policy.token_expired" for item in accepted.findings)


@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_supported_hmac_algorithms_can_be_checked_with_bounded_wordlist(algorithm):
    secret = f"M2-test-secret-{algorithm}-only-" + ("x" * 80)
    token = jwt.encode({"sub": "hmac-test"}, secret, algorithm=algorithm)
    candidates = (value for value in ("wrong-one", "wrong-two", secret))

    assert (
        brute_force_parallel(
            token,
            candidates,
            workers=4,
            algorithms=(algorithm,),
            timeout=2,
        )
        == secret
    )


def test_asymmetric_algorithms_are_not_available_to_hmac_secret_testing():
    private, algorithm, _ = _make_key("RSA")
    token = jwt.encode({"sub": "no-hmac"}, private, algorithm=algorithm)

    assert (
        brute_force_parallel(
            token,
            ["candidate"],
            workers=1,
            algorithms=("RS256",),
            timeout=2,
        )
        is None
    )
