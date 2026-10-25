"""M0 regression tests for token-only JWT finding semantics."""

import base64
import json

from click.testing import CliRunner

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
