"""Security and contract tests for the optional HTTP service."""

import asyncio
import base64
import json
import logging
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from core.parser import MAX_TOKEN_LENGTH
from jwt_analyzer import service
from jwt_analyzer.service import (
    _WindowRateLimiter,
    RequestTimeoutMiddleware,
    create_app,
    main,
)


def _client(app):
    return TestClient(
        app,
        base_url="http://127.0.0.1",
        headers={"host": "127.0.0.1"},
        raise_server_exceptions=False,
    )


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


def test_health_probes_openapi_and_security_headers():
    client = _client(create_app())

    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.headers["cache-control"] == "no-store"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["x-frame-options"] == "DENY"
    assert health.headers["x-request-id"]

    assert client.get("/api/v1/health/live").json()["status"] == "alive"
    assert client.get("/api/v1/health/ready").json()["status"] == "ready"

    spec_response = client.get("/api/v1/openapi.json")
    assert spec_response.status_code == 200
    spec = spec_response.json()
    assert "/api/v1/inspect" in spec["paths"]
    assert "/api/v1/verify" in spec["paths"]
    assert "/api/v1/health/ready" in spec["paths"]
    assert not any("jwks" in path.lower() for path in spec["paths"])
    assert spec["components"]["schemas"]["InspectRequest"]["additionalProperties"] is False
    assert spec["components"]["schemas"]["VerifyRequest"]["additionalProperties"] is False


def test_readiness_fails_closed_during_shutdown():
    app = create_app()
    client = _client(app)
    app.state.ready = False

    response = client.get("/api/v1/health/ready")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "http_error"


def test_inspect_returns_assessment_without_original_token():
    client = _client(create_app())
    token = _token()
    response = client.post("/api/v1/inspect", json={"token": token})

    assert response.status_code == 200, response.text
    assessment = response.json()
    assert assessment["verification_status"] == "not_attempted"
    assert assessment["claims"]["sub"] == "service-test"
    assert "token" not in assessment
    assert token not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_authentication_protects_both_assessment_routes():
    api_token = "t" * 40
    client = _client(create_app(api_token=api_token))
    inspect_payload = {"token": _token()}
    verify_payload = {
        "token": _token(),
        "public_key": "-----BEGIN PUBLIC KEY-----",
        "algorithms": ["RS256"],
    }

    for payload, route in (
        (inspect_payload, "/api/v1/inspect"),
        (verify_payload, "/api/v1/verify"),
    ):
        missing = client.post(route, json=payload)
        wrong = client.post(
            route,
            json=payload,
            headers={"Authorization": "Bearer wrong-token"},
        )
        accepted = client.post(
            route,
            json=payload,
            headers={"Authorization": "Bearer " + api_token},
        )
        assert missing.status_code == 401
        assert wrong.status_code == 401
        assert accepted.status_code != 401
        assert missing.headers["www-authenticate"] == "Bearer"


def test_verify_uses_inline_public_key_and_asymmetric_allowlist():
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
    client = _client(create_app())
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


@pytest.mark.parametrize(
    "key_content",
    [
        "https://attacker.example/key.pem",
        '{"kty":"RSA","n":"AQAB","e":"AQAB","x5u":"http://127.0.0.1:8080/internal"}',
        '{"kty":"RSA","n":"AQAB","e":"AQAB","jku":"http://169.254.169.254/latest/"}',
        '{"kty":"RSA","n":"AQAB","e":"AQAB","url":"http://127.0.0.1/"}',
        '{"keys":[]}',
    ],
)
def test_verify_rejects_remote_key_references_and_key_sets(key_content):
    client = _client(create_app())
    response = client.post(
        "/api/v1/verify",
        json={"token": _token(), "public_key": key_content, "algorithms": ["RS256"]},
    )

    assert response.status_code == 422
    assert "remote" not in response.text.lower() or "forbidden" in response.text.lower()


def test_unknown_jwks_url_fields_are_rejected_without_echoing_input():
    client = _client(create_app())
    remote_url = "http://169.254.169.254/latest/meta-data/"
    response = client.post(
        "/api/v1/verify",
        json={
            "token": _token(),
            "public_key": "-----BEGIN PUBLIC KEY-----",
            "algorithms": ["RS256"],
            "jwks_url": remote_url,
        },
    )

    assert response.status_code == 422
    assert remote_url not in response.text
    assert response.json()["error"]["code"] == "invalid_request"


def test_request_schema_is_strict_and_validation_errors_do_not_echo_tokens():
    client = _client(create_app())
    secret = "sensitive-request-body-value"
    response = client.post(
        "/api/v1/inspect",
        json={"token": secret, "unexpected": "must-not-be-accepted"},
    )

    assert response.status_code == 422
    assert secret not in response.text
    assert "must-not-be-accepted" not in response.text
    assert response.json()["error"]["code"] == "invalid_request"


def test_malformed_json_uses_stable_error_envelope():
    client = _client(create_app())
    response = client.post(
        "/api/v1/inspect",
        content=b'{"token":',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_json"


def test_request_body_limit_is_enforced_before_json_parsing():
    client = _client(create_app(max_request_bytes=96))
    response = client.post(
        "/api/v1/inspect",
        content=json.dumps({"token": "x" * 200}),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"


def test_streamed_request_body_limit_applies_without_content_length():
    app = create_app(max_request_bytes=32)
    messages = [
        {"type": "http.request", "body": b'{"token":"12345678901234567890"', "more_body": True},
        {"type": "http.request", "body": b'xxxxxxxxxxxxxxxxxxxxxxxx', "more_body": False},
    ]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/inspect",
        "raw_path": b"/api/v1/inspect",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"127.0.0.1"), (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 80),
    }
    asyncio.run(app(scope, receive, send))

    start = next(message for message in sent if message["type"] == "http.response.start")
    body = next(message for message in sent if message["type"] == "http.response.body")
    assert start["status"] == 413
    assert b"request_too_large" in body["body"]


def test_request_timeout_middleware_stops_slow_body_readers():
    async def slow_app(scope, receive, send):
        await receive()

    async def blocked_receive():
        await asyncio.sleep(0.2)
        return {"type": "http.disconnect"}

    async def capture_send(message):
        sent.append(message)

    sent = []
    scope = {"type": "http"}
    middleware = RequestTimeoutMiddleware(slow_app, timeout_seconds=0.01)
    asyncio.run(middleware(scope, blocked_receive, capture_send))

    start = next(message for message in sent if message["type"] == "http.response.start")
    body = next(message for message in sent if message["type"] == "http.response.body")
    assert start["status"] == 408
    assert b"request_timeout" in body["body"]


def test_request_rate_limit_is_applied_to_assessment_routes():
    client = _client(create_app(requests_per_minute=1))
    first = client.post("/api/v1/inspect", json={"token": _token()})
    second = client.post("/api/v1/inspect", json={"token": _token()})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limited"


def test_untrusted_host_header_is_rejected():
    client = _client(create_app())
    response = client.post(
        "/api/v1/inspect",
        json={"token": _token()},
        headers={"Host": "attacker.example"},
    )

    assert response.status_code == 400


def test_dashboard_uses_nonce_csp_and_text_only_result_rendering():
    client = _client(create_app())
    response = client.get("/dashboard")

    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "script-src 'nonce-" in csp
    assert 'nonce="' in response.text
    assert "result.textContent = JSON.stringify(data, null, 2)" in response.text
    assert "localStorage" not in response.text
    assert "sessionStorage" not in response.text


def test_large_jwt_is_rejected_even_when_json_body_is_under_request_cap():
    client = _client(create_app())
    response = client.post(
        "/api/v1/inspect",
        json={"token": "a" * (MAX_TOKEN_LENGTH + 1)},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_remote_bind_requires_explicit_opt_in_bearer_secret_and_host_allowlist():
    with pytest.raises(SystemExit):
        main(["--host", "0.0.0.0"])
    with pytest.raises(SystemExit):
        main(["--host", "0.0.0.0", "--allow-remote"])
    with pytest.raises(SystemExit):
        main(
            [
                "--host",
                "0.0.0.0",
                "--allow-remote",
                "--api-token",
                "t" * 40,
            ]
        )
    with pytest.raises(SystemExit):
        main(
            [
                "--host",
                "0.0.0.0",
                "--allow-remote",
                "--api-token",
                "t" * 40,
                "--allowed-host",
                "*",
            ]
        )
    with pytest.raises(SystemExit):
        main(
            [
                "--host",
                "0.0.0.0",
                "--allow-remote",
                "--api-token",
                "short",
                "--allowed-host",
                "analyzer.internal.example",
            ]
        )


def test_rate_limiter_caps_client_state():
    limiter = _WindowRateLimiter(limit=1)
    for index in range(4096):
        assert limiter.allow("client-" + str(index)) is True

    assert len(limiter._counts) == 4096
    assert limiter.allow("new-client") is False
    assert len(limiter._counts) == 4096


@pytest.mark.parametrize(
    "kwargs",
    [
        {"api_token": "short"},
        {"max_request_bytes": 8 * 1024 * 1024 + 1},
        {"requests_per_minute": 0},
        {"request_timeout_seconds": 0},
        {"max_concurrent_assessments": 0},
        {"max_concurrent_assessments": 33},
        {"allowed_hosts": ["*"]},
    ],
)
def test_app_configuration_rejects_unsafe_or_out_of_range_values(kwargs):
    with pytest.raises(ValueError):
        create_app(**kwargs)


def test_empty_auth_token_is_rejected():
    with pytest.raises(ValueError):
        create_app(api_token=" ")


def test_unexpected_exceptions_do_not_leak_data_to_responses_or_logs(monkeypatch, caplog):
    secret = "do-not-log-this-token"

    def explode(_token):
        raise RuntimeError(secret)

    monkeypatch.setattr(service, "inspect_token", explode)
    caplog.set_level(logging.INFO, logger="jwt_analyzer.service")
    client = _client(create_app())
    response = client.post("/api/v1/inspect", json={"token": _token()})

    assert response.status_code == 500
    assert secret not in response.text
    assert secret not in caplog.text
    assert response.json()["error"]["code"] == "internal_error"
    assert response.headers["x-request-id"]


def test_access_logs_are_structured_and_do_not_include_request_bodies(caplog):
    token = _token(claims={"sub": "log-secret-marker", "exp": 4102444800})
    caplog.set_level(logging.INFO, logger="jwt_analyzer.service")
    client = _client(create_app())
    response = client.post("/api/v1/inspect", json={"token": token})

    assert response.status_code == 200
    assert '"event":"http_request"' in caplog.text
    assert '"status_code":200' in caplog.text
    assert token not in caplog.text
    assert "log-secret-marker" not in caplog.text


def test_lifecycle_marks_app_unready_after_shutdown():
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1", headers={"host": "127.0.0.1"}) as client:
        assert client.get("/api/v1/health/ready").status_code == 200
    assert app.state.ready is False
