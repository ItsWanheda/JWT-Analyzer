"""Adversarial regression tests for JWKS destination validation."""

import json
import socket
from unittest.mock import Mock

import pytest

import core.jwks as jwks


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
PRIVATE_V6 = (
    socket.AF_INET6,
    socket.SOCK_STREAM,
    socket.IPPROTO_TCP,
    "",
    ("::1", 443, 0, 0),
)


@pytest.fixture(autouse=True)
def clear_cache():
    jwks.clear_cache()
    yield
    jwks.clear_cache()


@pytest.mark.parametrize(
    "url",
    [
        "http://jwks.example.test/keys",
        "https://user:secret@jwks.example.test/keys",
        "https://jwks.example.test/keys#fragment",
        "https://2130706433/keys",
        "https://0x7f000001/keys",
        "https://127.0.0.1/keys",
        "https://[::1]/keys",
        "https://jwks.example.test:99999/keys",
        "https://jwks.example.test/keys\r\nHost: attacker.test",
    ],
)
def test_rejects_unsafe_or_noncanonical_urls(url):
    with pytest.raises(ValueError):
        jwks._validate_jwks_url(url)


def test_rejects_mixed_public_and_private_dns_answers(monkeypatch):
    monkeypatch.setattr(
        jwks.socket, "getaddrinfo", lambda *_args, **_kwargs: [PUBLIC_V4, PRIVATE_V4]
    )
    with pytest.raises(ValueError, match="non-public"):
        jwks._validate_jwks_url("https://mixed.example.test/keys")


def test_rejects_private_ipv6_dns_answer(monkeypatch):
    monkeypatch.setattr(
        jwks.socket, "getaddrinfo", lambda *_args, **_kwargs: [PRIVATE_V6]
    )
    with pytest.raises(ValueError, match="non-public"):
        jwks._validate_jwks_url("https://v6.example.test/keys")


def test_private_override_still_returns_pinned_destination(monkeypatch):
    calls = []

    def resolve(host, port, **kwargs):
        calls.append((host, port))
        return [PRIVATE_V4]

    monkeypatch.setattr(jwks.socket, "getaddrinfo", resolve)
    dest = jwks._validate_jwks_url(
        "https://internal.example.test/keys", allow_private_hosts=True
    )
    assert dest.addresses == (PRIVATE_V4,)
    assert calls == [("internal.example.test", 443)]


def test_connection_uses_ip_socket_and_original_tls_hostname(monkeypatch):
    raw_socket = Mock()
    tls_socket = Mock()
    context = Mock()
    context.wrap_socket.return_value = tls_socket
    conn = jwks._PinnedHTTPSConnection(
        "jwks.example.test", 443, (PUBLIC_V4,), timeout=3
    )
    conn._context = context
    monkeypatch.setattr(
        jwks.socket, "socket", lambda family, socktype, proto: raw_socket
    )
    conn.connect()
    raw_socket.connect.assert_called_once_with(("93.184.216.34", 443))
    context.wrap_socket.assert_called_once_with(
        raw_socket, server_hostname="jwks.example.test"
    )
    tls_socket.settimeout.assert_called_once_with(3.0)
    conn.close()


class FakeResponse:
    def __init__(self, body, status=200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers or {"Content-Type": "application/json"}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, amount):
        return self.body[:amount]


def install_fake_http(monkeypatch, response):
    calls = []

    def resolve(host, port, **kwargs):
        calls.append((host, port))
        return [PUBLIC_V4]

    monkeypatch.setattr(jwks.socket, "getaddrinfo", resolve)
    connections = []

    class FakeConnection:
        def __init__(self, hostname, port, addresses, timeout):
            self.hostname = hostname
            self.port = port
            self.addresses = addresses
            self.timeout = timeout
            self.request_args = None
            self.closed = False
            connections.append(self)

        def request(self, method, target, headers):
            self.request_args = (method, target, headers)

        def getresponse(self):
            return response

        def close(self):
            self.closed = True

    monkeypatch.setattr(jwks, "_PinnedHTTPSConnection", FakeConnection)
    return calls, connections


def test_fetch_passes_validated_dns_answers_to_connection_without_second_lookup(monkeypatch):
    payload = {"keys": [{"kty": "RSA", "kid": "one", "n": "AQAB", "e": "AQAB"}]}
    response = FakeResponse(json.dumps(payload).encode())
    calls, connections = install_fake_http(monkeypatch, response)
    result = jwks.fetch_jwks("https://jwks.example.test/keys?tenant=test")
    assert result == payload
    assert calls == [("jwks.example.test", 443)]
    assert len(connections) == 1
    assert connections[0].addresses == (PUBLIC_V4,)
    method, target, headers = connections[0].request_args
    assert (method, target) == ("GET", "/keys?tenant=test")
    assert headers["Host"] == "jwks.example.test"
    assert headers["Accept-Encoding"] == "identity"
    assert connections[0].closed is True


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (
            FakeResponse(b"{}", status=302, headers={"Location": "https://private.test"}),
            "redirects",
        ),
        (FakeResponse(b"{}", headers={"Content-Type": "text/html"}), "JSON content type"),
        (
            FakeResponse(
                b"{}",
                headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            ),
            "Compressed",
        ),
        (
            FakeResponse(
                b"{}",
                headers={"Content-Type": "application/json", "Content-Length": "999999999"},
            ),
            "size limit",
        ),
        (FakeResponse(b"{broken"), "valid UTF-8 JSON"),
    ],
)
def test_fails_closed_on_unsafe_or_malformed_responses(monkeypatch, response, message):
    install_fake_http(monkeypatch, response)
    with pytest.raises(ValueError, match=message):
        jwks.fetch_jwks("https://jwks.example.test/keys")


def test_oversized_body_is_bounded(monkeypatch):
    response = FakeResponse(
        b"x" * (jwks.MAX_JWKS_BYTES + 10),
        headers={"Content-Type": "application/json"},
    )
    install_fake_http(monkeypatch, response)
    with pytest.raises(ValueError, match="1 MiB"):
        jwks.fetch_jwks("https://jwks.example.test/oversized")


@pytest.mark.parametrize(
    "keys",
    [
        [{"kty": "RSA", "kid": "one", "d": "private"}],
        [{"kty": "oct", "kid": "one", "k": "symmetric"}],
        [{"kty": "RSA", "kid": 3}],
        [{"kty": "RSA", "kid": "one", "key_ops": "verify"}],
    ],
)
def test_rejects_private_or_malformed_jwks_entries(monkeypatch, keys):
    response = FakeResponse(json.dumps({"keys": keys}).encode())
    install_fake_http(monkeypatch, response)
    with pytest.raises(ValueError):
        jwks.fetch_jwks("https://jwks.example.test/malformed")


def test_cache_returns_copies_and_revalidates_urls_on_hits(monkeypatch):
    payload = {"keys": [{"kty": "RSA", "kid": "trusted", "n": "AQAB", "e": "AQAB"}]}
    response = FakeResponse(json.dumps(payload).encode())
    calls, connections = install_fake_http(monkeypatch, response)
    first = jwks.fetch_jwks("https://jwks.example.test/cached")
    first["keys"][0]["kid"] = "poisoned"
    second = jwks.fetch_jwks("https://jwks.example.test/cached")
    assert second == payload
    assert len(connections) == 1
    assert len(calls) == 2


@pytest.mark.parametrize("algorithm", ["none", "HS256", ""])
def test_rejects_non_asymmetric_allowlists(algorithm):
    result = jwks.verify_with_jwks(
        "not-a-token", "https://jwks.example.test/keys", algorithms=[algorithm]
    )
    assert result["status"] == "error"
    assert result["verified"] is False
