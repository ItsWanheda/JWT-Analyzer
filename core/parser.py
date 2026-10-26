"""Strict compact-JWT structure decoding; claim policy is evaluated separately."""

from __future__ import annotations

import base64
import binascii
import json
import math
from datetime import datetime, timezone
from typing import Any

MAX_TOKEN_LENGTH = 1_048_576
_ALLOWED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _base64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment or any(c not in _ALLOWED for c in segment):
        raise ValueError("JWT segment contains invalid Base64URL characters")
    if len(segment) % 4 == 1:
        raise ValueError("Invalid Base64URL segment length")
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Base64URL encoding") from exc


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JWT contains a non-finite JSON number: {value}")


def _json_object(segment: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            _base64url_decode(segment),
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON in JWT {label}") from exc
    except ValueError as exc:
        raise ValueError(f"Invalid JSON value in JWT {label}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JWT {label} must be a JSON object")
    return value


def _expiry_info(payload: dict[str, Any]) -> dict[str, Any]:
    """Build optional display metadata without enforcing application claim policy."""
    if "exp" not in payload:
        return {}
    exp = payload["exp"]
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return {"invalid_claim_type": "exp"}
    try:
        numeric_exp = float(exp)
    except (OverflowError, ValueError):
        return {"timestamp_out_of_range": True}
    if not math.isfinite(numeric_exp):
        return {"timestamp_out_of_range": True}
    try:
        exp_datetime = datetime.fromtimestamp(numeric_exp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return {"timestamp_out_of_range": True}
    remaining = numeric_exp - datetime.now(timezone.utc).timestamp()
    return {
        "exp_timestamp": exp,
        "remaining_seconds": remaining,
        "is_expired": remaining < 0,
        "exp_datetime": exp_datetime.strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def parse_jwt(token: str) -> dict[str, Any]:
    """Decode compact-JWT structure only; decoded claims remain untrusted."""
    if not isinstance(token, str) or not token.strip():
        raise ValueError("JWT must be a non-empty string")
    token = token.strip()
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError(f"JWT exceeds maximum length of {MAX_TOKEN_LENGTH} characters")
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise ValueError("Invalid JWT format: expected three non-empty segments")

    header = _json_object(parts[0], "header")
    payload = _json_object(parts[1], "payload")
    if parts[2]:
        _base64url_decode(parts[2])
    return {
        "header": header,
        "payload": payload,
        "expiry_info": _expiry_info(payload),
        "signature_present": bool(parts[2]),
        "verified": False,
        "warning": (
            "Decoded claims are untrusted until a separate signature-verification and "
            "claim-policy stage succeeds."
        ),
    }
