"""Security and contract tests for the optional HTTP service."""
import base64
import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from core.parser import MAX_TOKEN_LENGTH
from jwt_analyzer.service import create_app, main


def _segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _token(header=None, claims=None, signature="c2lnbmF0dXJl"):
    return ".".join(
        (
            _segment(header if header is not None else {"alg": "HS256", "typ": "JWT"}),
            _segment(claims if claims is not None else {"sub": "service-test", "exp": 4102444800}),
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


def test_health_endpoint_and_security_headers():
    client = TestClient(create_app())
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "cache-control" in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in response.headers


def test_inspect_endpoint_returns_structured_assessment_without_original_token():
    client = TestClient(create_app())
    token = _token()
    response = client.post("/api/v1/inspect", json={"token": token})

    assert response.status_code == 200, response.text
    assessment = response.json()
    assert assessment["verification_status"] == "not_attempted"
    assert assessment["claims"]["sub"] == "service-test"
    assert "token" not in assessment
    assert token not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_authentication_is_required_when_token_is_configured():
    token = "t" * 40
    client = TestClient(create_app(api_token=token))
    payload = {"token": _token()}

    assert client.post("/api/v1/inspect", json=payload).status_code == 401
    assert client.post(
        "/api/v1/inspect",
        json=payload,
        headers={"Authorization": "Bearer wrong-token"},
    ).status_code == 401
    accepted = client.post(
        "/api/v1/inspect",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert accepted.status_code == 200


def test_verify_endpoint_uses_explicit_key_and_asymmetric_allowlist():
    private_key, public_key = _rsa_key_pair()
    compact = jwt.encode(
        {
            "sub": "service-verified-user",
            "exp": 4102444800,
            "iss": "https://issuer.example",
            "aud": "jwt-api",
        },
        private_key,
        algorithm="RS256",
    )
    client = TestClient(create_app())
    response = client.post(
        "/api/v1/verify",
        json={
            "token": compact,
            "public_key": public_key,
            "algorithms": ["RS256"],
            "issuer": "https://issuer.example",
            "audience": "jwt-api",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["verification_status"] == "verified"
    assert response.json()["claims"]["sub"] == "service-verified-user"

    rejected = client.post(
        "/api/v1/verify",
        json={"token": compact, "public_key": public_key, "algorithms": ["HS256"]},
    )
    assert rejected.status_code == 422


def test_request_body_limit_applies_before_json_parsing():
    client = TestClient(create_app(max_request_bytes=96))
    response = client.post(
        "/api/v1/inspect",
        content=json.dumps({"token": "x" * 200}),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "size limit" in response.json()["detail"].lower()


def test_request_rate_limit_is_applied_to_assessment_routes():
    client = TestClient(create_app(requests_per_minute=1))
    first = client.post("/api/v1/inspect", json={"token": _token()})
    second = client.post("/api/v1/inspect", json={"token": _token()})

    assert first.status_code == 200
    assert second.status_code == 429


def test_dashboard_uses_nonce_csp_and_text_only_result_rendering():
    client = TestClient(create_app())
    response = client.get("/dashboard")

    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "script-src 'nonce-" in csp
    assert "nonce=\"" in response.text
    assert "result.textContent = JSON.stringify(data, null, 2)" in response.text
    assert "localStorage" not in response.text
    assert "sessionStorage" not in response.text


def test_large_jwt_is_rejected_even_when_json_body_is_under_request_cap():
    client = TestClient(create_app())
    response = client.post(
        "/api/v1/inspect",
        json={"token": "a" * (MAX_TOKEN_LENGTH + 1)},
    )

    assert response.status_code == 413


def test_remote_bind_requires_explicit_opt_in_and_bearer_secret(monkeypatch):
    with pytest.raises(SystemExit):
        main(["--host", "0.0.0.0"])
    with pytest.raises(SystemExit):
        main(["--host", "0.0.0.0", "--allow-remote"])


def test_empty_auth_token_is_rejected():
    with pytest.raises(ValueError):
        create_app(api_token="   ")
