import base64
import json

import pytest

from core.parser import parse_jwt
from core.security import check_algorithm_confusion
from core.jwks import _validate_jwks_url
from utils.report import generate_html_report


def _segment(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def _token(header=None, payload=None, signature="sig"):
    return ".".join((_segment(header if header is not None else {"alg": "HS256"}), _segment(payload if payload is not None else {"sub": "demo"}), signature))


def test_parser_marks_decoded_claims_unverified():
    result = parse_jwt(_token(payload={"sub": "demo", "exp": 4102444800}))
    assert result["verified"] is False
    assert result["payload"]["sub"] == "demo"
    assert result["expiry_info"]["is_expired"] is False


@pytest.mark.parametrize("token", ["", "a.b.c", "!!!!.e30.sig", _token(payload=[]), _token(payload={"exp": "tomorrow"})])
def test_parser_rejects_malformed_segments_and_claims(token):
    with pytest.raises(ValueError):
        parse_jwt(token)


def test_parser_can_inspect_unsigned_token_without_trusting_it():
    result = parse_jwt(_token(header={"alg": "none"}, signature=""))
    assert result["signature_present"] is False
    assert result["verified"] is False


def test_algorithm_confusion_is_not_claimed_from_header_alone():
    result = check_algorithm_confusion(_token(header={"alg": "RS256"}))
    assert result["is_asymmetric"] is True
    assert result["vulnerable_to_confusion"] is False
    assert "cannot establish" in result["finding"]


def test_jwks_url_requires_https_and_public_destination():
    with pytest.raises(ValueError):
        _validate_jwks_url("http://example.com/jwks.json")
    with pytest.raises(ValueError):
        _validate_jwks_url("https://127.0.0.1/jwks.json")


def test_html_report_escapes_untrusted_values_and_redacts_token(tmp_path):
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature-long-enough-for-redaction"
    output = tmp_path / "report.html"
    generate_html_report({
        "analyst": "<script>alert(1)</script>",
        "token_info": {"token": token, "note": "<img src=x onerror=alert(1)>"},
        "payload": {"email": "person@example.test"},
        "findings": [{
            "severity": "HIGH", "title": "<script>alert(1)</script>",
            "description": "unsafe <b>value</b>", "remediation": "fix it",
            "type": "custom",
        }],
    }, str(output), analyst="<script>alert(1)</script>")
    rendered = output.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert token not in rendered
    assert "[REDACTED]" in rendered
