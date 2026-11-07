"""Contract tests for the v2 JSON CLI."""

import json

from click.testing import CliRunner

from jwt_analyzer.cli_v2 import cli


def _segment(value):
    import base64

    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")


def _token(subject):
    return ".".join(
        (
            _segment({"alg": "HS256", "typ": "JWT"}),
            _segment({"sub": subject, "exp": 4102444800}),
            "c2ln",
        )
    )


def test_inspect_cli_emits_one_machine_readable_json_document(tmp_path):
    token_file = tmp_path / "token.jwt"
    token_file.write_text(_token("cli-user"), encoding="utf-8")

    result = CliRunner().invoke(cli, ["inspect", "--token-file", str(token_file)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["assessment"]["verification_status"] == "not_attempted"


def test_inspect_cli_structured_errors_go_to_stderr(tmp_path):
    token_file = tmp_path / "bad.jwt"
    token_file.write_text("invalid", encoding="utf-8")

    result = CliRunner().invoke(cli, ["inspect", "--token-file", str(token_file)])

    assert result.exit_code == 1
    error = json.loads(result.output)
    assert error["status"] == "error"
    assert error["error"]["code"] == "invalid_token"


def test_batch_cli_streams_per_item_results_and_reports_partial_failure(tmp_path):
    input_file = tmp_path / "batch.txt"
    input_file.write_text(_token("one") + "\ninvalid\n" + _token("three") + "\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["batch", "--input-file", str(input_file)])

    assert result.exit_code == 1
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    assert [line["status"] for line in lines] == ["succeeded", "failed", "succeeded", "partial"]
    assert lines[-1]["summary"] == {"processed": 3, "succeeded": 2, "failed": 1}


def test_batch_cli_obeys_configured_item_limit(tmp_path):
    input_file = tmp_path / "batch.txt"
    input_file.write_text(_token("one") + "\n" + _token("two") + "\n", encoding="utf-8")
    config_file = tmp_path / "config.json"
    config_file.write_text('{"max_batch_items": 1}', encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["batch", "--input-file", str(input_file), "--config", str(config_file)],
    )

    assert result.exit_code == 2
    error = json.loads(result.output.splitlines()[-1])
    assert error["error"]["code"] == "batch_limit_exceeded"
