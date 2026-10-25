"""Regression tests for safe default report and logging redaction."""

import json
import logging

from core.logging_config import JSONFormatter
from utils.io import read_token_from_file
from utils.report import generate_html_report, redact_sensitive_data


def test_redaction_removes_pii_tokens_and_scanner_matches():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
    report = {
        "payload": {
            "sub": "person@example.test",
            "name": "Example Person",
            "custom_contact": "person@example.test",
            "nested_token": token,
        },
        "pii_details": {
            "findings_by_severity": {
                "CRITICAL": [{"type": "credit_card", "matched_text": "4111111111111111"}]
            }
        },
    }
    rendered = json.dumps(redact_sensitive_data(report))
    assert token not in rendered
    assert "person@example.test" not in rendered
    assert "Example Person" not in rendered
    assert "4111111111111111" not in rendered
    assert "[REDACTED]" in rendered
    inline_credential = redact_sensitive_data({"message": "token=plain-secret-value"})
    assert "plain-secret-value" not in inline_credential["message"]


def test_log_formatter_redacts_tokens_and_inline_credentials():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
    record = logging.LogRecord(
        "test",
        logging.ERROR,
        __file__,
        1,
        "Request failed token=%s Authorization: Bearer %s",
        (token, "very-secret-bearer-value"),
        None,
    )
    formatted = JSONFormatter().format(record)
    assert token not in formatted
    assert "very-secret-bearer-value" not in formatted
    assert "[REDACTED]" in formatted


def test_malformed_token_error_omits_input_contents(tmp_path):
    path = tmp_path / "malformed.jwt"
    path.write_text("secret-fragment.alpha.beta.extra", encoding="utf-8")
    try:
        read_token_from_file(str(path))
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected malformed input to be rejected")
    assert "secret-fragment" not in message
    assert "Token contents are omitted" in message


def test_html_report_redacts_sensitive_finding_text_and_analyst(tmp_path):
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
    output = tmp_path / "report.html"
    generate_html_report(
        {
            "findings": [
                {
                    "type": "custom_finding",
                    "severity": "HIGH",
                    "title": "Sensitive data",
                    "description": f"Leaked person@example.test token={token}",
                    "remediation": "Rotate credentials.",
                }
            ],
            "token_info": {
                "raw_token": token,
                "account_email": "metadata@example.test",
            },
            "payload": {
                "sub": "payload@example.test",
                "access_token": token,
            },
        },
        str(output),
        analyst="analyst@example.test",
    )
    html = output.read_text(encoding="utf-8")
    assert token not in html
    assert "person@example.test" not in html
    assert "analyst@example.test" not in html
    assert "metadata@example.test" not in html
    assert "payload@example.test" not in html
