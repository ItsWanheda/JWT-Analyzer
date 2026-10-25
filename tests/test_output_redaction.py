"""Regression tests for safe default report and logging redaction."""

import json
import logging

from core.logging_config import JSONFormatter
from utils.io import read_token_from_file
from utils.report import redact_sensitive_data


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
                "CRITICAL": [
                    {"type": "credit_card", "matched_text": "4111111111111111"}
                ]
            }
        },
    }
    rendered = json.dumps(redact_sensitive_data(report))
    assert token not in rendered
    assert "person@example.test" not in rendered
    assert "Example Person" not in rendered
    assert "4111111111111111" not in rendered
    assert "[REDACTED]" in rendered


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
