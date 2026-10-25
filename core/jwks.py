"""Defensive JWKS retrieval with DNS-pinned HTTPS connections."""

import copy
import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import jwt

logger = logging.getLogger(__name__)
MAX_JWKS_BYTES = 1_048_576
MAX_JWKS_KEYS = 1000
_DEFAULT_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_NUMERIC_HOST_RE = re.compile(r"(?i)(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*\Z")


@dataclass(frozen=True)
class _JWKSLocation:
    """Validated destination and the address tuples allowed for connection."""

    hostname: str
    port: int
    addresses: tuple
    request_target: str
    host_header: str


class _JWKSCache:
    """In-memory cache with defensive copies of fetched key material."""

    def __init__(self, ttl: int = 3600):
        self.ttl = max(0, ttl)
        self._store: dict[str, tuple[dict, float]] = {}

    def get(self, url: str) -> Optional[dict]:
        entry = self._store.get(url)
        if entry is None:
            return None
        data, fetched_at = entry
        if time.monotonic() - fetched_at > self.ttl:
            self._store.pop(url, None)
            return None
        return copy.deepcopy(data)

    def set(self, url: str, data: dict) -> None:
        self._store[url] = (copy.deepcopy(data), time.monotonic())

    def clear(self) -> None:
        self._store.clear()


_cache = _JWKSCache()


def clear_cache() -> None:
    """Clear the in-memory JWKS cache."""
    _cache.clear()


def _validate_jwks_url(url: str, allow_private_hosts: bool = False) -> _JWKSLocation:
    """Validate URL syntax and DNS answers, and return the pinned destination.

    By default all resolved addresses must be globally routable. Mixed public
    and private answers fail closed. DNS answers returned here are reused by the
    HTTPS connection, preventing a second hostname lookup at connect time.
    """
    if not isinstance(url, str) or not url or len(url) > 8192:
        raise ValueError("JWKS URL must be a non-empty string no longer than 8192 characters")
    if not isinstance(allow_private_hosts, bool):
        raise ValueError("allow_private_hosts must be a boolean")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in url):
        raise ValueError("JWKS URL contains whitespace or control characters")
    try:
        parsed = urlsplit(url)
        raw_hostname = parsed.hostname
        port = parsed.port or 443
    except (TypeError, ValueError) as exc:
        raise ValueError("JWKS URL is malformed") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("JWKS URL must use HTTPS")
    if (
        not raw_hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("JWKS URL must have a hostname and no credentials or fragment")
    if not 1 <= port <= 65535:
        raise ValueError("JWKS URL port is invalid")

    hostname = raw_hostname.rstrip(".").lower()
    if not hostname:
        raise ValueError("JWKS URL hostname is invalid")
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        # Reject platform-specific decimal, octal, or hexadecimal IPv4 forms.
        if _NUMERIC_HOST_RE.fullmatch(hostname):
            raise ValueError("IP literals must use canonical IPv4 or IPv6 notation") from None
        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("JWKS hostname is invalid") from exc
        labels = hostname.split(".")
        if len(hostname) > 253 or any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("JWKS hostname is invalid") from None
    else:
        hostname = str(literal_ip)

    if not allow_private_hosts and (hostname == "localhost" or hostname.endswith(".localhost")):
        raise ValueError("JWKS URL may not target localhost")
    try:
        addresses = tuple(socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM))
    except (OSError, UnicodeError) as exc:
        raise ValueError("JWKS hostname could not be resolved") from exc
    if not addresses:
        raise ValueError("JWKS hostname resolved to no addresses")
    for info in addresses:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        except (IndexError, TypeError, ValueError) as exc:
            raise ValueError("JWKS hostname resolved to an invalid address") from exc
        if not allow_private_hosts and not ip.is_global:
            raise ValueError("JWKS URL resolves to a non-public IP address")

    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if port != 443:
        host_header = f"{host_header}:{port}"
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return _JWKSLocation(hostname, port, addresses, target, host_header)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS connection that never resolves the original hostname again."""

    def __init__(self, hostname: str, port: int, addresses: tuple, timeout: float):
        self._validated_addresses = addresses
        self._connect_timeout = min(float(timeout), 5.0)
        super().__init__(
            host=hostname,
            port=port,
            timeout=float(timeout),
            context=ssl.create_default_context(),
        )

    def connect(self) -> None:
        if self._tunnel_host:
            raise ConnectionError("JWKS proxy tunnels are not supported")
        last_error = None
        for family, socktype, proto, _canonname, sockaddr in self._validated_addresses:
            raw_socket = None
            try:
                raw_socket = socket.socket(family, socktype, proto)
                raw_socket.settimeout(self._connect_timeout)
                # sockaddr already contains the validated IP address.
                raw_socket.connect(sockaddr)
                tls_socket = self._context.wrap_socket(raw_socket, server_hostname=self.host)
                tls_socket.settimeout(self.timeout)
                self.sock = tls_socket
                return
            except ssl.SSLCertVerificationError:
                if raw_socket is not None:
                    raw_socket.close()
                raise
            except (OSError, ssl.SSLError) as exc:
                if raw_socket is not None:
                    raw_socket.close()
                last_error = exc
        raise ConnectionError("Unable to connect to the validated JWKS destination") from last_error


def fetch_jwks(
    url: str,
    timeout: int = 10,
    verify_ssl: bool = True,
    allow_private_hosts: bool = False,
) -> dict:
    """Fetch JWKS over verified TLS with DNS pinning, no redirects, and size caps."""
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
        or timeout > 60
    ):
        raise ValueError("timeout must be greater than 0 and at most 60 seconds")
    if not verify_ssl:
        raise ValueError("TLS certificate verification cannot be disabled")

    # Validate on cache hits too; an entry fetched with the explicit private-host
    # override must never bypass the default policy later.
    destination = _validate_jwks_url(url, allow_private_hosts)
    cached = _cache.get(url)
    if cached is not None:
        return cached

    connection = _PinnedHTTPSConnection(
        destination.hostname, destination.port, destination.addresses, float(timeout)
    )
    try:
        connection.request(
            "GET",
            destination.request_target,
            headers={
                "Host": destination.host_header,
                "User-Agent": "jwt-analyzer/2.0",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ValueError("JWKS redirects are disabled; configure the final HTTPS URL")
        if not 200 <= response.status < 300:
            raise ValueError(f"JWKS endpoint returned HTTP status {response.status}")

        content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        if (
            content_type
            and content_type != "application/json"
            and not content_type.endswith("+json")
        ):
            raise ValueError("JWKS endpoint did not return a JSON content type")
        encoding = (response.getheader("Content-Encoding") or "identity").lower().strip()
        if encoding not in ("", "identity"):
            raise ValueError("Compressed JWKS responses are not supported")

        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except (TypeError, ValueError) as exc:
                raise ValueError("JWKS response has an invalid Content-Length") from exc
            if declared_length < 0:
                raise ValueError("JWKS response has an invalid Content-Length")
            if declared_length > MAX_JWKS_BYTES:
                raise ValueError("JWKS response exceeds the 1 MiB size limit")
        raw = response.read(MAX_JWKS_BYTES + 1)
        if len(raw) > MAX_JWKS_BYTES:
            raise ValueError("JWKS response exceeds the 1 MiB size limit")
    except ValueError:
        raise
    except ssl.SSLCertVerificationError as exc:
        raise ConnectionError("TLS certificate verification failed for JWKS endpoint") from exc
    except ssl.SSLError as exc:
        raise ConnectionError("TLS connection failed for JWKS endpoint") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise ConnectionError(f"Timed out fetching JWKS after {timeout:g}s") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise ConnectionError("Failed to fetch JWKS from the validated destination") from exc
    finally:
        connection.close()

    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("JWKS response is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise ValueError("JWKS response must be a JSON object with a keys array")
    if len(data["keys"]) > MAX_JWKS_KEYS:
        raise ValueError("JWKS contains too many keys")
    for key_data in data["keys"]:
        if not isinstance(key_data, dict) or not isinstance(key_data.get("kty"), str):
            raise ValueError("JWKS contains a malformed key entry")
        if key_data["kty"] not in {"RSA", "EC", "OKP"}:
            raise ValueError("JWKS contains an unsupported public key type")
        if _PRIVATE_JWK_MEMBERS.intersection(key_data):
            raise ValueError("JWKS must not contain private or symmetric key material")
        for field in ("kid", "alg", "use"):
            if key_data.get(field) is not None and not isinstance(key_data[field], str):
                raise ValueError(f"JWKS key field {field} must be a string")
        key_ops = key_data.get("key_ops")
        if key_ops is not None and (
            not isinstance(key_ops, list) or any(not isinstance(item, str) for item in key_ops)
        ):
            raise ValueError("JWKS key_ops must be an array of strings")
    _cache.set(url, data)
    return copy.deepcopy(data)


def _find_key(jwks: dict, kid: str):
    matches = [key for key in jwks.get("keys", []) if key.get("kid") == kid]
    if len(matches) > 1:
        raise ValueError("JWKS contains duplicate matching kid values")
    return matches[0] if matches else None


def verify_with_jwks(
    token: str,
    jwks_url: str,
    algorithms: Optional[list] = None,
    verify_ssl: bool = True,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    leeway: int = 0,
    allow_private_hosts: bool = False,
) -> dict:
    """Verify a JWT with a configured JWKS and an explicit asymmetric allowlist."""
    if algorithms is None:
        algorithms = sorted(_DEFAULT_ALGORITHMS)
    if (
        isinstance(algorithms, (str, bytes))
        or not isinstance(algorithms, (list, tuple))
        or not algorithms
        or any(not isinstance(alg, str) or not alg for alg in algorithms)
        or len(set(algorithms)) != len(algorithms)
        or not set(algorithms).issubset(_DEFAULT_ALGORITHMS)
    ):
        return {
            "status": "error",
            "verified": False,
            "error": "A non-empty allowlist of supported asymmetric algorithms is required",
        }
    if not verify_ssl:
        return {
            "status": "error",
            "verified": False,
            "error": "TLS certificate verification cannot be disabled",
        }
    if isinstance(leeway, bool) or not isinstance(leeway, (int, float)) or leeway < 0:
        return {"status": "error", "verified": False, "error": "leeway must be non-negative"}
    if not isinstance(token, str) or not token or len(token) > 1_048_576:
        return {
            "status": "error",
            "verified": False,
            "error": "JWT is empty or exceeds the size limit",
        }

    try:
        header = jwt.get_unverified_header(token)
        kid, alg = header.get("kid"), header.get("alg")
        if not isinstance(kid, str) or not kid:
            return {
                "status": "error",
                "verified": False,
                "error": "Token must contain a non-empty kid",
            }
        if alg not in algorithms:
            return {
                "status": "invalid",
                "verified": False,
                "error": "Token algorithm is not in the configured allowlist",
            }
        jwks = fetch_jwks(jwks_url, verify_ssl=verify_ssl, allow_private_hosts=allow_private_hosts)
        key_data = _find_key(jwks, kid)
        if key_data is None:
            return {
                "status": "error",
                "verified": False,
                "error": "kid was not found in the configured JWKS",
            }

        compatible = {
            "RSA": {"RS256", "RS384", "RS512"},
            "EC": {"ES256", "ES384", "ES512"},
            "OKP": {"EdDSA"},
        }
        key_type = key_data.get("kty")
        if alg not in compatible.get(key_type, set()):
            return {
                "status": "invalid",
                "verified": False,
                "error": "JWT algorithm and JWK key type are incompatible",
            }
        if key_data.get("use") not in (None, "sig"):
            return {
                "status": "invalid",
                "verified": False,
                "error": "Selected JWK is not marked for signatures",
            }
        if key_data.get("alg") not in (None, alg):
            return {
                "status": "invalid",
                "verified": False,
                "error": "Selected JWK algorithm does not match JWT algorithm",
            }
        if key_data.get("key_ops") is not None and "verify" not in key_data["key_ops"]:
            return {
                "status": "invalid",
                "verified": False,
                "error": "Selected JWK does not permit verification",
            }
        if key_type == "RSA":
            key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
        elif key_type == "EC":
            key = jwt.algorithms.ECAlgorithm.from_jwk(key_data)
        else:
            key = jwt.algorithms.OKPAlgorithm.from_jwk(key_data)
        payload = jwt.decode(
            token,
            key,
            algorithms=list(algorithms),
            issuer=issuer,
            audience=audience,
            leeway=leeway,
        )
        return {"status": "valid", "verified": True, "payload": payload, "kid": kid}
    except jwt.InvalidTokenError:
        return {
            "status": "invalid",
            "verified": False,
            "error": "JWT signature or configured claim validation failed",
        }
    except (ConnectionError, ValueError, TypeError):
        return {
            "status": "error",
            "verified": False,
            "error": "JWKS retrieval or verification could not be completed",
        }
    except Exception:
        logger.error("Unexpected error in JWKS verification")
        return {"status": "error", "verified": False, "error": "Unexpected verification failure"}
