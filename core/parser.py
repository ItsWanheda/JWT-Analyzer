"""Strict JWT structure decoding. Decoding does not verify signatures."""
import base64
import binascii
import json
from datetime import datetime, timezone
from typing import Any

MAX_TOKEN_LENGTH = 1_048_576
_ALLOWED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


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


def _json_object(segment: str, label: str) -> dict:
    try:
        value = json.loads(_base64url_decode(segment))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON in JWT {label}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JWT {label} must be a JSON object")
    return value


def parse_jwt(token: str) -> dict[str, Any]:
    """Decode header and payload without asserting that they are trusted."""
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
    expiry_info = {}
    if "exp" in payload:
        exp = payload["exp"]
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise ValueError("JWT exp claim must be a numeric timestamp")
        try:
            exp_datetime = datetime.fromtimestamp(float(exp), tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("JWT exp claim is outside the supported timestamp range") from exc
        remaining = float(exp) - datetime.now(timezone.utc).timestamp()
        expiry_info = {
            "exp_timestamp": exp, "remaining_seconds": remaining,
            "is_expired": remaining < 0,
            "exp_datetime": exp_datetime.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    return {
        "header": header, "payload": payload, "expiry_info": expiry_info,
        "signature_present": bool(parts[2]), "verified": False,
        "warning": "Decoded claims are untrusted until signature and claim validation succeed.",
    }
