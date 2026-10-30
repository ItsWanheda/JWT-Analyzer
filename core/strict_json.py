"""Strict JSON decoding for security-sensitive token and key material."""

from __future__ import annotations

import json
import math
from typing import Any

MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_JSON_INTEGER_DIGITS = 128


def _parse_integer(value: str) -> int:
    digits = value.lstrip("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds the supported digit limit")
    return int(value)


def _parse_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON numbers must be finite")
    return number


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-standard JSON numeric constant is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _validate_string(value: str) -> None:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError("JSON strings must not contain unpaired UTF-16 surrogates")


def _validate_tree(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_NODES:
            raise ValueError("JSON document contains too many values")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON document exceeds the maximum nesting depth")
        if isinstance(current, str):
            _validate_string(current)
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("JSON numbers must be finite")
        elif isinstance(current, dict):
            for key, item in current.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                _validate_string(key)
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def strict_json_loads(
    data: str | bytes,
    *,
    max_bytes: int | None = None,
) -> Any:
    """Decode UTF-8 JSON while rejecting duplicates and resource-amplifying values."""
    if isinstance(data, bytes):
        raw = data
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("JSON input must be valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
        try:
            raw = data.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("JSON input must contain valid Unicode") from exc
    else:
        raise TypeError("JSON input must be str or bytes")

    if max_bytes is not None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        if len(raw) > max_bytes:
            raise ValueError("JSON input exceeds its configured size limit")

    try:
        value = json.loads(
            text,
            parse_int=_parse_integer,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("JSON input is malformed or too deeply nested") from exc
    _validate_tree(value)
    return value
