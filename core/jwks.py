"""Defensive JWKS retrieval and verification helpers."""
import ipaddress
import json
import logging
import socket
import time
from urllib.parse import urlparse
from typing import Optional, Dict

import jwt
import requests

logger = logging.getLogger(__name__)
MAX_JWKS_BYTES = 1_048_576


class _JWKSCache:
    def __init__(self, ttl: int = 3600):
        self.ttl = max(0, ttl)
        self._store: Dict[str, tuple] = {}

    def get(self, url: str) -> Optional[dict]:
        entry = self._store.get(url)
        if entry is None:
            return None
        data, fetched_at = entry
        if time.monotonic() - fetched_at > self.ttl:
            self._store.pop(url, None)
            return None
        return data

    def set(self, url: str, data: dict):
        self._store[url] = (data, time.monotonic())

    def clear(self):
        self._store.clear()


_cache = _JWKSCache()


def clear_cache():
    _cache.clear()


def _validate_jwks_url(url: str, allow_private_hosts: bool = False) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("JWKS URL must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("JWKS URL must have a hostname and no credentials or fragment")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" and not allow_private_hosts:
        raise ValueError("JWKS URL may not target localhost")
    try:
        addresses = {ipaddress.ip_address(hostname)}
    except ValueError:
        try:
            addresses = {ipaddress.ip_address(item[4][0]) for item in
                         socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise ValueError("JWKS hostname could not be resolved") from exc
    if not allow_private_hosts and any(not address.is_global for address in addresses):
        raise ValueError("JWKS URL resolves to a non-public IP address")


def fetch_jwks(url: str, timeout: int = 10, verify_ssl: bool = True,
               allow_private_hosts: bool = False) -> dict:
    """Fetch a size-limited JWKS from HTTPS; redirects and insecure TLS are rejected."""
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 60:
        raise ValueError("timeout must be greater than 0 and at most 60 seconds")
    if not verify_ssl:
        raise ValueError("TLS certificate verification cannot be disabled for JWKS retrieval")
    _validate_jwks_url(url, allow_private_hosts)
    cached = _cache.get(url)
    if cached is not None:
        return cached
    try:
        with requests.get(url, timeout=(min(float(timeout), 5.0), float(timeout)),
                          verify=True, allow_redirects=False, stream=True,
                          headers={"User-Agent": "jwt-analyzer/1.2", "Accept": "application/json"}) as response:
            if 300 <= response.status_code < 400:
                raise ValueError("JWKS redirects are disabled; configure the final HTTPS URL")
            response.raise_for_status()
            content_type = response.headers.get("Content-Type", "").lower()
            if content_type and "json" not in content_type:
                raise ValueError("JWKS endpoint did not return a JSON content type")
            chunks, total = [], 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_JWKS_BYTES:
                    raise ValueError("JWKS response exceeds the 1 MiB size limit")
                chunks.append(chunk)
            raw = b"".join(chunks)
    except requests.exceptions.SSLError as exc:
        raise ConnectionError("TLS verification failed for JWKS endpoint") from exc
    except requests.exceptions.Timeout as exc:
        raise ConnectionError(f"Timed out fetching JWKS after {timeout}s") from exc
    except requests.exceptions.RequestException as exc:
        raise ConnectionError(f"Failed to fetch JWKS: {exc}") from exc
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("JWKS response is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise ValueError("JWKS response must be a JSON object with a keys array")
    if len(data["keys"]) > 1000 or any(not isinstance(k, dict) or not isinstance(k.get("kty"), str) for k in data["keys"]):
        raise ValueError("JWKS contains too many keys or a malformed key entry")
    _cache.set(url, data)
    return data


def _find_key(jwks: dict, kid: str):
    matches = [key for key in jwks.get("keys", []) if key.get("kid") == kid]
    if len(matches) > 1:
        raise ValueError("JWKS contains duplicate matching kid values")
    return matches[0] if matches else None


def verify_with_jwks(token: str, jwks_url: str, algorithms: Optional[list] = None,
                     verify_ssl: bool = True, issuer: Optional[str] = None,
                     audience: Optional[str] = None, leeway: int = 0,
                     allow_private_hosts: bool = False) -> dict:
    """Verify against a caller-configured JWKS URL and explicit algorithm allowlist."""
    if algorithms is None:
        algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
    if not algorithms or any(not isinstance(a, str) or not a for a in algorithms):
        return {"status": "error", "verified": False, "error": "A non-empty algorithm allowlist is required"}
    if not verify_ssl:
        return {"status": "error", "verified": False, "error": "TLS verification cannot be disabled"}
    if leeway < 0:
        return {"status": "error", "verified": False, "error": "leeway must be non-negative"}
    try:
        header = jwt.get_unverified_header(token)
        kid, alg = header.get("kid"), header.get("alg")
        if not isinstance(kid, str) or not kid:
            return {"status": "error", "verified": False, "error": "Token must contain a non-empty kid"}
        if alg not in algorithms:
            return {"status": "invalid", "verified": False, "error": "Token algorithm is not in the configured allowlist"}
        jwks = fetch_jwks(jwks_url, verify_ssl=verify_ssl, allow_private_hosts=allow_private_hosts)
        key_data = _find_key(jwks, kid)
        if key_data is None:
            return {"status": "error", "verified": False, "error": "kid was not found in the configured JWKS"}
        kty = key_data.get("kty")
        compatible = {"RSA": {"RS256", "RS384", "RS512"},
                      "EC": {"ES256", "ES384", "ES512"}, "OKP": {"EdDSA"}}
        if alg not in compatible.get(kty, set()):
            return {"status": "invalid", "verified": False, "error": "JWT algorithm and JWK key type are incompatible"}
        if key_data.get("use") not in (None, "sig"):
            return {"status": "invalid", "verified": False, "error": "Selected JWK is not marked for signatures"}
        if key_data.get("alg") not in (None, alg):
            return {"status": "invalid", "verified": False, "error": "Selected JWK algorithm does not match JWT algorithm"}
        if key_data.get("key_ops") is not None and "verify" not in key_data["key_ops"]:
            return {"status": "invalid", "verified": False, "error": "Selected JWK does not permit verification"}
        if kty == "RSA":
            key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
        elif kty == "EC":
            key = jwt.algorithms.ECAlgorithm.from_jwk(key_data)
        elif kty == "OKP" and alg == "EdDSA":
            key = jwt.algorithms.OKPAlgorithm.from_jwk(key_data)
        else:
            return {"status": "error", "verified": False, "error": f"Unsupported JWK key type: {kty}"}
        payload = jwt.decode(token, key, algorithms=list(algorithms), issuer=issuer,
                             audience=audience, leeway=leeway)
        return {"status": "valid", "verified": True, "payload": payload, "kid": kid}
    except jwt.InvalidTokenError as exc:
        return {"status": "invalid", "verified": False, "error": str(exc)}
    except (ConnectionError, ValueError, TypeError) as exc:
        return {"status": "error", "verified": False, "error": str(exc)}
    except Exception:
        logger.exception("Unexpected error in JWKS verification")
        return {"status": "error", "verified": False, "error": "Unexpected verification failure"}
