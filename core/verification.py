"""Cryptographic JWT verification helpers."""
from typing import Optional

import jwt

from core.parser import MAX_TOKEN_LENGTH, parse_jwt
from core.strict_json import strict_json_loads

DEFAULT_ASYMMETRIC_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"]

_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


MAX_PUBLIC_KEY_BYTES = 65_536


def _load_public_key(key_content: str):
    if not isinstance(key_content, str):
        raise TypeError("Public key content must be a string")
    try:
        encoded_length = len(key_content.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise ValueError("Public key content contains invalid Unicode") from exc
    if encoded_length > MAX_PUBLIC_KEY_BYTES:
        raise ValueError("Public key content exceeds the 64 KiB size limit")
    key_content = key_content.strip()
    if not key_content:
        raise ValueError("Public key content must not be empty")
    if key_content.startswith("{"):
        jwk = strict_json_loads(key_content, max_bytes=MAX_PUBLIC_KEY_BYTES)
        if not isinstance(jwk, dict):
            raise ValueError("JWK must be a JSON object")
        if _PRIVATE_JWK_MEMBERS.intersection(jwk):
            raise ValueError("Private or symmetric JWK material is not accepted")
        if jwk.get("use") not in (None, "sig"):
            raise ValueError("JWK is not marked for signature use")
        key_ops = jwk.get("key_ops")
        if key_ops is not None:
            if (
                not isinstance(key_ops, list)
                or any(not isinstance(item, str) or not item for item in key_ops)
                or len(key_ops) != len(set(key_ops))
            ):
                raise ValueError("JWK key_ops must be an array of unique operation names")
            if "verify" not in key_ops:
                raise ValueError("JWK key_ops does not permit verification")
        algorithm = jwk.get("alg")
        if algorithm is not None and (not isinstance(algorithm, str) or not algorithm):
            raise ValueError("JWK alg must be a non-empty string")
        key_type = jwk.get("kty")
        if key_type == "RSA":
            return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        if key_type == "EC":
            return jwt.algorithms.ECAlgorithm.from_jwk(jwk)
        if key_type == "OKP":
            return jwt.algorithms.OKPAlgorithm.from_jwk(jwk)
        raise ValueError(f"Unsupported JWK key type: {key_type!r}")
    if "BEGIN PUBLIC KEY" not in key_content and "BEGIN RSA PUBLIC KEY" not in key_content:
        raise ValueError("Expected a PEM public key or supported public JWK")
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_public_key(key_content.encode("utf-8"))


def verify_with_public_key(token: str, key_content: str,
                           algorithms: Optional[list] = None,
                           issuer: Optional[str] = None,
                           audience: Optional[str] = None,
                           leeway: int = 0) -> dict:
    """Verify signature and optional issuer/audience claims using an allowlist."""
    if algorithms is None:
        algorithms = DEFAULT_ASYMMETRIC_ALGORITHMS
    if not algorithms or any(not isinstance(alg, str) or not alg for alg in algorithms):
        return {"status": "error", "verified": False, "error": "A non-empty algorithm allowlist is required"}
    if leeway < 0:
        return {"status": "error", "verified": False, "error": "leeway must be non-negative"}
    try:
        key = _load_public_key(key_content)
        payload = jwt.decode(token, key, algorithms=list(algorithms), issuer=issuer,
                             audience=audience, leeway=leeway,
                             options={"verify_signature": True, "verify_exp": True,
                                      "verify_nbf": True, "verify_iat": True})
        return {"status": "valid", "payload": payload, "verified": True,
                "validation": {"algorithms": list(algorithms), "issuer": issuer,
                               "audience": audience, "leeway_seconds": leeway}}
    except jwt.InvalidTokenError:
        return {
            "status": "invalid",
            "verified": False,
            "error": "JWT signature or configured claim validation failed",
        }
    except (ValueError, TypeError):
        return {
            "status": "error",
            "verified": False,
            "error": "Public key or verification configuration is invalid",
        }
    except Exception:
        return {
            "status": "error",
            "verified": False,
            "error": "Verification could not be completed",
        }

def verify_signature_with_public_key(
    token: str,
    key_content: str,
    algorithms: list[str],
) -> dict:
    """Verify the cryptographic signature only; do not apply JWT claim policy."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
        return {
            "status": "error",
            "verified": False,
            "error": "Token is empty or exceeds the configured size limit",
        }
    if isinstance(algorithms, (str, bytes)) or not isinstance(algorithms, (list, tuple)):
        return {
            "status": "error",
            "verified": False,
            "error": "A non-empty asymmetric algorithm allowlist is required",
        }
    if (
        not algorithms
        or any(not isinstance(alg, str) or not alg for alg in algorithms)
        or len(set(algorithms)) != len(algorithms)
        or set(algorithms).difference(DEFAULT_ASYMMETRIC_ALGORITHMS)
    ):
        return {
            "status": "error",
            "verified": False,
            "error": "A valid asymmetric algorithm allowlist is required",
        }
    try:
        parsed = parse_jwt(token)
    except (TypeError, ValueError):
        return {"status": "invalid", "verified": False, "error": "JWT structure is invalid"}

    token_algorithm = parsed["header"].get("alg")
    if not isinstance(token_algorithm, str) or token_algorithm not in algorithms:
        return {
            "status": "invalid",
            "verified": False,
            "error": "Token algorithm is not in the configured allowlist",
        }
    try:
        key = _load_public_key(key_content)
        if key_content.lstrip().startswith("{"):
            jwk = strict_json_loads(key_content, max_bytes=MAX_PUBLIC_KEY_BYTES)
            if jwk.get("alg") not in (None, token_algorithm):
                return {
                    "status": "invalid",
                    "verified": False,
                    "error": "JWK algorithm does not match JWT algorithm",
                }
        payload = jwt.decode(
            token,
            key,
            algorithms=list(algorithms),
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
                "verify_sub": False,
                "verify_jti": False,
                "require": [],
            },
        )
        if not isinstance(payload, dict):
            return {
                "status": "error",
                "verified": False,
                "error": "The verifier returned an unexpected payload type",
            }
        return {
            "status": "valid",
            "payload": payload,
            "verified": True,
            "validation": {"algorithms": list(algorithms), "mode": "signature_only"},
        }
    except jwt.InvalidTokenError:
        return {
            "status": "invalid",
            "verified": False,
            "error": "JWT signature verification failed",
        }
    except jwt.PyJWTError:
        return {
            "status": "invalid",
            "verified": False,
            "error": "JWT key type or verification algorithm is incompatible",
        }
    except (ValueError, TypeError):
        return {
            "status": "error",
            "verified": False,
            "error": "Public key or verification configuration is invalid",
        }
    except Exception:
        return {
            "status": "error",
            "verified": False,
            "error": "Signature verification could not be completed",
        }

