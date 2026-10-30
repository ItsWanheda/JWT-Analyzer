"""Deterministic property/fuzz-style tests for compact JWT and JSON boundaries."""

import base64
import json
import random

import pytest

from core.parser import MAX_TOKEN_LENGTH, _base64url_decode, parse_jwt


def _segment_bytes(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _token_from_json(header, payload):
    return ".".join(
        (
            _segment_bytes(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            _segment_bytes(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
            "",
        )
    )


@pytest.mark.parametrize("value", ["null", "[]", '"string"', "12", "true", "false"])
def test_header_and_payload_must_be_json_objects(value):
    segment = _segment_bytes(value.encode("utf-8"))
    valid_header = _segment_bytes(b'{"alg":"RS256"}')
    with pytest.raises(ValueError):
        parse_jwt(f"{segment}.{valid_header}.")
    with pytest.raises(ValueError):
        parse_jwt(f"{valid_header}.{segment}.")


@pytest.mark.parametrize(
    "raw_payload",
    [
        b'{"exp":NaN}',
        b'{"exp":Infinity}',
        b'{"exp":-Infinity}',
        b'{"exp":1e9999}',
        b'{"exp":' + (b"9" * 140) + b"}",
        b'{"sub":"\\ud800"}',
        b'{"sub":"ok","sub":"ambiguous"}',
    ],
)
def test_numeric_unicode_and_duplicate_json_edge_cases_are_rejected(raw_payload):
    header = _segment_bytes(b'{"alg":"RS256"}')
    with pytest.raises(ValueError):
        parse_jwt(f"{header}.{_segment_bytes(raw_payload)}.")


def test_duplicate_algorithm_header_is_rejected():
    header = _segment_bytes(b'{"alg":"RS256","alg":"none"}')
    payload = _segment_bytes(b'{"sub":"duplicate-header"}')

    with pytest.raises(ValueError, match="Duplicate"):
        parse_jwt(f"{header}.{payload}.")


def test_noncanonical_base64url_padding_bits_are_rejected():
    with pytest.raises(ValueError, match="canonical"):
        _base64url_decode("ex")


def test_parser_rejects_tokens_over_the_size_limit():
    oversized = "a" * (MAX_TOKEN_LENGTH + 1)
    with pytest.raises(ValueError, match="maximum length"):
        parse_jwt(oversized)


def test_parser_handles_deterministic_unicode_and_numeric_corpus():
    rng = random.Random(0x4A5754)
    unicode_values = [
        "plain-ascii",
        "café",
        "e\u0301",
        "日本語",
        "مرحبا",
        "עברית",
        "ქართული",
        "हिन्दी",
        "😀",
        "👩🏽‍💻",
    ]

    for index in range(200):
        text = rng.choice(unicode_values)
        payload = {
            "sub": f"property-{index}",
            "label": text,
            "counter": rng.randint(-(10**12), 10**12),
            "fraction": rng.uniform(-1_000_000, 1_000_000),
            "exp": 4_102_444_800,
        }
        assessment = parse_jwt(_token_from_json({"alg": "RS256"}, payload))
        assert assessment["payload"] == payload
        assert assessment["verified"] is False


def test_random_invalid_utf8_payloads_fail_with_controlled_value_errors():
    rng = random.Random(0x4D32)
    header = _segment_bytes(b'{"alg":"RS256"}')

    for _ in range(250):
        raw = bytes([0xFF]) + bytes(rng.randrange(0, 256) for _ in range(32))
        with pytest.raises(ValueError):
            parse_jwt(f"{header}.{_segment_bytes(raw)}.")


@pytest.mark.parametrize("depth", [65, 80, 100])
def test_excessively_nested_json_is_rejected(depth):
    nested = b'{"value":' * depth + b"0" + b"}" * depth
    header = _segment_bytes(b'{"alg":"RS256"}')
    with pytest.raises(ValueError, match="nesting"):
        parse_jwt(f"{header}.{_segment_bytes(nested)}.")


def test_parser_keeps_unusual_but_valid_unicode_claims_verbatim():
    value = "line one\nline two\t\u200f\u202e\u2066"
    token = _token_from_json({"alg": "RS256"}, {"sub": "unicode", "display": value})

    parsed = parse_jwt(token)

    assert parsed["payload"]["display"] == value



def test_parser_accepts_and_normalizes_valid_escaped_surrogate_pairs():
    header = _segment_bytes(b'{"alg":"RS256"}')
    payload = _segment_bytes(
        b'{"sub":"\\ud83d\\ude00","\\ud83d\\ude80":"rocket"}'
    )

    parsed = parse_jwt(f"{header}.{payload}.")

    assert parsed["payload"]["sub"] == "😀"
    assert parsed["payload"]["🚀"] == "rocket"


def test_parser_rejects_keys_that_collide_after_unicode_normalization():
    header = _segment_bytes(b'{"alg":"RS256"}')
    payload = _segment_bytes('{"\\ud83d\\ude00":"escaped","😀":"literal"}'.encode("utf-8"))

    with pytest.raises(ValueError, match="Duplicate JSON object key"):
        parse_jwt(f"{header}.{payload}.")
