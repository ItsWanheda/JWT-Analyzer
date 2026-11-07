"""M3 public API, batch, and configuration contract tests."""

import base64
import json

import pytest

from jwt_analyzer import (
    BatchLimitError,
    ConfigurationError,
    TokenAssessmentError,
    assess_many,
    inspect_token,
    iter_assessments,
)
from jwt_analyzer.config import load_config


def _segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _token(subject="m3-test"):
    return ".".join(
        (
            _segment({"alg": "HS256", "typ": "JWT"}),
            _segment({"sub": subject, "exp": 4102444800}),
            "c2ln",
        )
    )


def test_public_api_exports_are_explicit_and_exceptions_are_stable():
    assert "inspect_token" in __import__("jwt_analyzer").__all__
    with pytest.raises(TokenAssessmentError):
        inspect_token("not-a-jwt")


def test_batch_streams_results_and_keeps_going_after_bad_items():
    seen = []

    def source():
        for value in (_token("first"), "invalid", _token("third")):
            seen.append(value)
            yield value

    results = iter_assessments(source(), max_items=3)
    first = next(results)
    assert first.succeeded
    assert len(seen) == 1
    second = next(results)
    assert not second.succeeded
    assert second.error_code == "invalid_token"
    third = next(results)
    assert third.succeeded
    assert third.index == 2
    assert len(seen) == 3


def test_batch_limit_is_hard_and_does_not_materialize_input():
    results = iter_assessments(iter([_token(), _token(), _token()]), max_items=2)
    assert next(results).succeeded
    assert next(results).succeeded
    with pytest.raises(BatchLimitError):
        next(results)


def test_batch_rejects_invalid_limit():
    with pytest.raises(ValueError):
        list(assess_many([], max_items=0))


def test_config_default_and_environment_precedence():
    config = load_config(
        environ={
            "JWT_ANALYZER_POLICY": "strict",
            "JWT_ANALYZER_MAX_BATCH_ITEMS": "25",
            "JWT_ANALYZER_WORDLIST_PATH": "~/wordlists/custom.txt",
        }
    )
    assert config.policy.name == "strict"
    assert config.max_batch_items == 25
    assert str(config.wordlist_path).endswith("wordlists/custom.txt")


def test_config_file_values_are_overridden_by_environment(tmp_path):
    config_path = tmp_path / "jwt-analyzer.json"
    config_path.write_text(
        json.dumps({"policy": "baseline", "max_batch_items": 12}),
        encoding="utf-8",
    )
    config = load_config(
        config_path,
        environ={"JWT_ANALYZER_MAX_BATCH_ITEMS": "30"},
    )
    assert config.policy.name == "baseline"
    assert config.max_batch_items == 30


@pytest.mark.parametrize(
    "contents",
    [
        "[]",
        '{"unknown": true}',
        '{"max_batch_items": 0}',
        '{"policy": "unknown"}',
        '{"policy_options": {"unexpected": true}}',
    ],
)
def test_config_rejects_invalid_shapes_and_options(tmp_path, contents):
    path = tmp_path / "invalid.json"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(path, environ={})


def test_config_uses_safe_yaml_loader(tmp_path):
    path = tmp_path / "unsafe.yaml"
    path.write_text("policy: !!python/object/apply:os.system ['echo unsafe']", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(path, environ={})
