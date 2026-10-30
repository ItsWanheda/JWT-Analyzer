"""M2 adversarial JWKS key selection, metadata, TLS, cache, and DNS tests."""

import socket
import ssl

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import core.jwks


PUBLIC_V4 = (
    socket.AF_INET,
    socket.SOCK_STREAM,
    socket.IPPROTO_TCP,
    "",
    ("93.184.216.34", 443),
)
PRIVATE_V4 = (
    socket.AF_INET,
    socket.SOCK_STREAM,
    socket.IPPROTO_TCP,
    "",
    ("127.0.0.1", 443),
)


@pytest.fixture(autouse=True)
def clear_cache():
    core.jwks.clear_cache()
    yield
    core.jwks.clear_cache()


def _rsa_token_and_jwk(**metadata):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    public_jwk.update({"kid": "active-key", **metadata})
    token = jwt.encode(
        {"sub": "jwks-m2"},
        private,
        algorithm="RS256",
        headers={"kid": "active-key"},
    )
    return token, public_jwk


def test_duplicate_kid_is_rejected_as_ambiguous():
    first = {"kty": "RSA", "kid": "same", "n": "AQAB", "e": "AQAB"}
    second = {"kty": "RSA", "kid": "same", "n": "AQAC", "e": "AQAB"}

    with pytest.raises(ValueError, match="duplicate matching kid"):
        core.jwks._find_key({"keys": [first, second]}, "same")


def test_jwks_verification_rejects_duplicate_kid_without_selecting_first(monkeypatch):
    token, jwk = _rsa_token_and_jwk()
    duplicate = dict(jwk)
    duplicate["n"] = "AQAC"
    monkeypatch.setattr(
        core.jwks,
        "fetch_jwks",
        lambda *_args, **_kwargs: {"keys": [jwk, duplicate]},
    )

    result = core.jwks.verify_with_jwks(
        token,
        "https://keys.example.test/jwks",
        algorithms=["RS256"],
    )

    assert result["status"] == "error"
    assert result["verified"] is False


@pytest.mark.parametrize(
    ("metadata", "expected_error"),
    [
        ({"use": "enc"}, "not marked for signatures"),
        ({"key_ops": ["sign"]}, "does not permit verification"),
        ({"alg": "RS512"}, "algorithm does not match"),
        ({"key_ops": ["verify", "verify"]}, "malformed"),
    ],
)
def test_jwks_verification_rejects_use_key_ops_and_algorithm_mismatch(
    monkeypatch,
    metadata,
    expected_error,
):
    token, jwk = _rsa_token_and_jwk(**metadata)
    monkeypatch.setattr(
        core.jwks,
        "fetch_jwks",
        lambda *_args, **_kwargs: {"keys": [jwk]},
    )

    result = core.jwks.verify_with_jwks(
        token,
        "https://keys.example.test/jwks",
        algorithms=["RS256"],
    )

    assert result["status"] == "invalid"
    assert result["verified"] is False
    assert expected_error in result["error"]


def test_jwks_verification_rejects_key_type_algorithm_mismatch(monkeypatch):
    token, jwk = _rsa_token_and_jwk()
    jwk["kty"] = "EC"
    monkeypatch.setattr(
        core.jwks,
        "fetch_jwks",
        lambda *_args, **_kwargs: {"keys": [jwk]},
    )

    result = core.jwks.verify_with_jwks(
        token,
        "https://keys.example.test/jwks",
        algorithms=["RS256"],
    )

    assert result["status"] == "invalid"
    assert "incompatible" in result["error"]


def test_jwks_verification_succeeds_with_metadata_consistent_rsa_key(monkeypatch):
    token, jwk = _rsa_token_and_jwk(use="sig", key_ops=["verify"], alg="RS256")
    monkeypatch.setattr(
        core.jwks,
        "fetch_jwks",
        lambda *_args, **_kwargs: {"keys": [jwk]},
    )

    result = core.jwks.verify_with_jwks(
        token,
        "https://keys.example.test/jwks",
        algorithms=["RS256"],
    )

    assert result["status"] == "valid"
    assert result["verified"] is True
    assert result["payload"]["sub"] == "jwks-m2"


def test_dns_change_after_validation_does_not_change_pinned_destination(monkeypatch):
    resolutions = []

    def resolve(*_args, **_kwargs):
        resolutions.append(len(resolutions))
        return [PUBLIC_V4] if len(resolutions) == 1 else [PRIVATE_V4]

    monkeypatch.setattr(core.jwks.socket, "getaddrinfo", resolve)

    class FakeConnection:
        def __init__(self, hostname, port, addresses, timeout, deadline=None):
            self.addresses = addresses
            self.closed = False

        def request(self, *_args, **_kwargs):
            return None

        def getresponse(self):
            class Response:
                status = 200

                def __init__(self):
                    self.read_complete = False

                def getheader(self, name, default=None):
                    return {"Content-Type": "application/json"}.get(name, default)

                def read1(self, _size):
                    if self.read_complete:
                        return b""
                    self.read_complete = True
                    return b'{"keys":[]}'

            return Response()

        def close(self):
            self.closed = True

    connections = []

    def make_connection(*args, **kwargs):
        connection = FakeConnection(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(core.jwks, "_PinnedHTTPSConnection", make_connection)
    result = core.jwks.fetch_jwks("https://rotate.example.test/keys")

    assert result == {"keys": []}
    assert len(resolutions) == 1
    assert connections[0].addresses == (PUBLIC_V4,)


def test_tls_certificate_failure_fails_closed(monkeypatch):
    monkeypatch.setattr(core.jwks.socket, "getaddrinfo", lambda *_args, **_kwargs: [PUBLIC_V4])

    class FailedTLSConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            raise ssl.SSLCertVerificationError("certificate mismatch")

        def close(self):
            pass

    monkeypatch.setattr(core.jwks, "_PinnedHTTPSConnection", FailedTLSConnection)

    with pytest.raises(ConnectionError, match="TLS certificate verification failed"):
        core.jwks.fetch_jwks("https://bad-certificate.example.test/keys")


def test_missing_jwks_content_type_is_rejected(monkeypatch):
    response = type(
        "Response",
        (),
        {
            "status": 200,
            "getheader": lambda self, _name, default=None: default,
            "read1": lambda self, _size: b'{"keys":[]}',
        },
    )()

    monkeypatch.setattr(core.jwks.socket, "getaddrinfo", lambda *_args, **_kwargs: [PUBLIC_V4])

    class Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return response

        def close(self):
            pass

    monkeypatch.setattr(core.jwks, "_PinnedHTTPSConnection", Connection)
    with pytest.raises(ValueError, match="JSON content type"):
        core.jwks.fetch_jwks("https://no-content-type.example.test/keys")


def test_jwks_json_rejects_duplicate_keys_and_non_finite_values(monkeypatch):
    payloads = [
        b'{"keys":[],"keys":[]}',
        b'{"keys":[{"kty":"RSA","kid":"x","n":1e9999,"e":"AQAB"}]}',
    ]

    for body in payloads:
        response = type(
            "Response",
            (),
            {
                "status": 200,
                "getheader": lambda self, name, default=None: (
                    "application/json" if name == "Content-Type" else default
                ),
                "read1": lambda self, _size, body=body: body,
            },
        )()

        monkeypatch.setattr(
            core.jwks.socket, "getaddrinfo", lambda *_args, **_kwargs: [PUBLIC_V4]
        )

        class Connection:
            def __init__(self, *_args, **_kwargs):
                pass

            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self, response=response):
                return response

            def close(self):
                pass

        monkeypatch.setattr(core.jwks, "_PinnedHTTPSConnection", Connection)
        with pytest.raises(ValueError):
            core.jwks.fetch_jwks("https://strict-json.example.test/keys")


def test_cache_expiry_and_outage_do_not_return_stale_keys(monkeypatch):
    url = "https://outage.example.test/keys"
    stale = {"keys": [{"kty": "RSA", "kid": "stale", "n": "AQAB", "e": "AQAB"}]}
    cache = core.jwks._JWKSCache(ttl=5)
    ticks = iter([100.0, 106.0])
    monkeypatch.setattr(core.jwks.time, "monotonic", lambda: next(ticks))
    cache.set(url, stale)

    assert cache.get(url) is None
    assert not cache._store


def test_expired_jwks_cache_fails_closed_during_network_outage(monkeypatch):
    url = "https://offline.example.test/keys"
    stale = {"keys": [{"kty": "RSA", "kid": "stale", "n": "AQAB", "e": "AQAB"}]}
    core.jwks._cache.set(url, stale)
    cached_data, cached_at = core.jwks._cache._store[url]
    core.jwks._cache._store[url] = (cached_data, cached_at - 1)
    core.jwks._cache.ttl = 0
    monkeypatch.setattr(core.jwks.socket, "getaddrinfo", lambda *_args, **_kwargs: [PUBLIC_V4])

    class OfflineConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            raise socket.timeout("offline")

        def close(self):
            pass

    monkeypatch.setattr(core.jwks, "_PinnedHTTPSConnection", OfflineConnection)

    with pytest.raises(ConnectionError):
        core.jwks.fetch_jwks(url)
    assert url not in core.jwks._cache._store


@pytest.mark.parametrize("ttl", [float("nan"), float("inf"), -1, 86_401, True])
def test_jwks_cache_rejects_invalid_ttl(ttl):
    with pytest.raises(ValueError, match="cache TTL"):
        core.jwks._JWKSCache(ttl=ttl)
