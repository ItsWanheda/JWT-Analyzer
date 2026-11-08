# JWKS Retrieval Security Model

JWT Analyzer treats remote JWKS retrieval as an untrusted-network operation. The implementation is intentionally restrictive and fails closed when it cannot establish a safe destination or complete a bounded request.

## Destination validation

- Only HTTPS URLs are accepted. Credentials, fragments, malformed ports, control characters, and non-canonical numeric IP forms are rejected.
- Hostnames are normalized through IDNA validation before resolution.
- By default, every DNS answer must be globally routable. Mixed public/private answers, localhost names, private, loopback, link-local, reserved, and otherwise non-global addresses are rejected.
- Validated DNS answers are pinned to the HTTPS connection. The connection uses the original hostname for TLS certificate verification and SNI, but opens the socket to the already-validated IP address. It does not resolve the hostname a second time.
- Redirects and proxy tunnels are not followed. TLS verification cannot be disabled.

## DNS and request deadlines

The absolute request deadline starts before hostname resolution and is shared by DNS waiting, TCP connection, TLS negotiation, and response reading.

The system resolver is synchronous on some supported platforms and cannot be force-cancelled portably. To keep caller latency and resource use bounded, resolution runs through one daemon worker with a single pending queue slot. A caller whose deadline expires returns a DNS timeout. If the operating-system lookup remains stuck, that one worker can remain occupied; further DNS lookups fail closed instead of creating unbounded threads or queued work. JWKS fetching becomes available again after the underlying resolver returns.

This is a deliberate availability trade-off: a stuck system resolver can temporarily prevent new remote JWKS fetches, but it does not hold the requesting thread past its configured deadline or create an unbounded worker pool.

## Response and key limits

- The response must be a successful 2xx response with `application/json` or a structured `+json` content type.
- Compressed response bodies are rejected.
- Declared and streamed response bodies are capped at 1 MiB; the number of keys is capped at 1,000.
- JSON parsing rejects duplicate object keys, non-finite numbers, excessive integer digits, invalid UTF-8, lone UTF-16 surrogates, excessive nesting, and excessive node counts. Valid escaped surrogate pairs are normalized to Unicode scalar values; keys colliding after normalization are rejected.
- Private and symmetric JWK material is rejected. Key metadata is type-checked, duplicate `key_ops` values are rejected, and selected keys must be compatible with the JWT algorithm and permit signature verification.
- A `kid` must select exactly one eligible key. Ambiguous duplicate matches fail closed.
- Cache entries are bounded and returned by copy. Expired cache entries are not used as stale fallback during a network outage.

## Testing

The adversarial test suites cover URL/SSRF policy, mixed DNS answers, DNS pinning, DNS timeout behavior, TLS failures, redirects, content types, response limits, malformed/ambiguous keys, key metadata, cache expiry, and network outages. See `tests/test_jwks_security.py` and `tests/test_m2_jwks_adversarial.py`.

## Operational note

A DNS timeout can leave the single daemon resolver occupied until the platform resolver returns. Monitor resolver health and outbound DNS availability in deployments. Do not work around failures by enabling private-host access, disabling TLS verification, allowing redirects, or using stale keys.
