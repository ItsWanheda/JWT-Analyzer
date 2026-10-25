"""Cryptographic JWT verification helpers."""
import json
from typing import Optional

import jwt

DEFAULT_ASYMMETRIC_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"]

_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


def _load_public_key(key_content: str):
    key_content = key_content.strip()
    if not key_content:
        raise ValueError("Public key content must not be empty")
    if key_content.startswith("{"):
        try:
            jwk = json.loads(key_content)
        except json.JSONDecodeError as exc:
            raise ValueError("Public key JSON is malformed") from exc
        if not isinstance(jwk, dict):
            raise ValueError("JWK must be a JSON object")
        if _PRIVATE_JWK_MEMBERS.intersection(jwk):
            raise ValueError("Private or symmetric JWK material is not accepted")
        kty = jwk.get("kty")
        if kty == "RSA":
            return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        if kty == "EC":
            return jwt.algorithms.ECAlgorithm.from_jwk(jwk)
        if kty == "OKP":
            return jwt.algorithms.OKPAlgorithm.from_jwk(jwk)
        raise ValueError(f"Unsupported JWK key type: {kty!r}")
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
