"""M0 regression tests for token-only JWT finding semantics."""

import base64
import json
from pathlib import Path

from click.testing import CliRunner

import main
from main import cli


def _segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_alg_none_is_an_indicator_not_a_confirmed_bypass(tmp_path):
    token = ".".join(
        (
            _segment({"alg": "none", "typ": "JWT"}),
            _segment({"sub": "m0-regression", "exp": 4102444800}),
            "",
        )
    )
    token_file = tmp_path / "unsigned.jwt"
    token_file.write_text(token, encoding="utf-8")
    output_basename = tmp_path / "assessment"

    result = CliRunner().invoke(
        cli,
        [
            "audit",
            "--token-file",
            str(token_file),
            "--skip-bruteforce",
            "--output",
            str(output_basename),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(output_basename.with_suffix(".json").read_text(encoding="utf-8"))
    finding = next(
        item for item in report["findings"] if item["type"] == "none_algorithm_indicator"
    )
    assert finding["severity"] == "MEDIUM"
    assert finding["confidence"] == "high"
    assert finding["confidence_scope"] == "token-header-observation-only"
    assert "does not establish" in finding["description"]
    assert "vulnerable to signature bypass" in finding["description"]


def test_recovered_signing_secret_is_not_written_to_default_reports(tmp_path, monkeypatch):
    recovered_secret = "M0-RECOVERED-SIGNING-SECRET-9a72e31d"
    token = ".".join(
        (
            _segment({"alg": "HS256", "typ": "JWT"}),
            _segment({"sub": "redaction-test", "exp": 4102444800}),
            "c2lnbmF0dXJl",
        )
    )
    token_file = tmp_path / "signed.jwt"
    token_file.write_text(token, encoding="utf-8")
    wordlist = tmp_path / "candidates.txt"
    wordlist.write_text("candidate-secret\\n", encoding="utf-8")
    output_basename = tmp_path / "secret-safe-report"
    monkeypatch.setattr(
        main,
        "brute_force_parallel",
        lambda *_args, **_kwargs: recovered_secret,
    )

    result = CliRunner().invoke(
        cli,
        [
            "audit",
            "--token-file",
            str(token_file),
            "--wordlist",
            str(wordlist),
            "--output",
            str(output_basename),
            "--format",
            "both",
        ],
    )

    assert result.exit_code == 2, result.output
    assert recovered_secret not in result.output
    json_report = output_basename.with_suffix(".json").read_text(encoding="utf-8")
    html_report = Path(f"{output_basename}.html").read_text(encoding="utf-8")
    assert recovered_secret not in json_report
    assert recovered_secret not in html_report
