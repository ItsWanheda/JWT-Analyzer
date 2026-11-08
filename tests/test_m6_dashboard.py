"""Dashboard, export endpoint, and accessibility/security regressions for M6."""


import pytest

pytest.importorskip("fastapi")
import jwt
from fastapi.testclient import TestClient

from jwt_analyzer.api import inspect_token
from jwt_analyzer.service import create_app


def _assessment():
    token = jwt.encode(
        {"sub": "dashboard-user", "email": "private@example.test", "exp": 4102444800},
        "dashboard-test-secret-with-more-than-thirty-two-bytes",
        algorithm="HS256",
    )
    return inspect_token(token)


def _client(app=None):
    return TestClient(
        app or create_app(),
        base_url="http://127.0.0.1",
        headers={"host": "127.0.0.1"},
    )


def test_dashboard_exposes_inspect_verify_compare_and_export_workflows():
    response = _client().get("/dashboard")
    assert response.status_code == 200
    assert "content-security-policy" in response.headers
    assert "script-src 'nonce-" in response.headers["content-security-policy"]
    assert 'nonce="' in response.text
    for marker in (
        'id="inspect-form"',
        'id="verify-form"',
        'id="compare-submit"',
        'id="export-submit"',
        'id="include-sensitive"',
        'aria-live="polite"',
        'result.textContent = safeReport.content',
        'output.textContent = JSON.stringify',
    ):
        assert marker in response.text
    assert "localStorage" not in response.text
    assert "sessionStorage" not in response.text
    assert "innerHTML" not in response.text


def test_report_endpoint_redacts_by_default_and_allows_explicit_opt_in():
    client = _client()
    payload = {"assessment": _assessment().to_dict(), "format": "json"}

    safe = client.post("/api/v1/report", json=payload)
    assert safe.status_code == 200, safe.text
    assert safe.json()["redaction_applied"] is True
    assert "private@example.test" not in safe.json()["content"]

    explicit = client.post(
        "/api/v1/report",
        json={**payload, "include_sensitive": True},
    )
    assert explicit.status_code == 200, explicit.text
    assert explicit.json()["redaction_applied"] is False
    assert "private@example.test" in explicit.json()["content"]


@pytest.mark.parametrize("report_format", ["json", "html", "sarif"])
def test_report_endpoint_supports_all_validated_export_formats(report_format):
    response = _client().post(
        "/api/v1/report",
        json={"assessment": _assessment().to_dict(), "format": report_format},
    )
    assert response.status_code == 200, response.text
    assert response.json()["format"] == report_format
    assert response.json()["redaction_applied"] is True
    assert isinstance(response.json()["content"], str)


def test_report_endpoint_rejects_invalid_assessments_and_extra_fields():
    client = _client()
    invalid = client.post(
        "/api/v1/report",
        json={"assessment": {"unexpected": "value"}, "format": "json"},
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "http_error"
    extra = client.post(
        "/api/v1/report",
        json={
            "assessment": _assessment().to_dict(),
            "format": "json",
            "include_sensitive": True,
            "untrusted": "field",
        },
    )
    assert extra.status_code == 422
    assert "untrusted" not in extra.text


def test_report_endpoint_uses_existing_bearer_authentication():
    client = _client(create_app(api_token="x" * 40))
    response = client.post(
        "/api/v1/report",
        json={"assessment": _assessment().to_dict(), "format": "json"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_report_endpoint_is_rate_limited():
    client = _client(create_app(requests_per_minute=1))
    payload = {"assessment": _assessment().to_dict(), "format": "json"}
    first = client.post("/api/v1/report", json=payload)
    second = client.post("/api/v1/report", json=payload)
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limited"


def test_openapi_documents_report_endpoint_and_strict_request_schema():
    spec = _client().get("/api/v1/openapi.json").json()
    assert "/api/v1/report" in spec["paths"]
    schema = spec["components"]["schemas"]["ReportRequest"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"assessment", "format"}
