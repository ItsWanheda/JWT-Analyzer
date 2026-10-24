# Optional HTTP Service and Dashboard

**Status:** unreleased v2 development functionality. The service is an opt-in interface over the shared assessment engine; it is not an authentication server or an authorization decision point.

## Install and run locally

Install the optional dependencies in an isolated environment:

```bash
python -m pip install -e ".[service]"
```

The service binds to loopback by default. Authentication can be enabled locally by exporting a bearer token before startup:

```bash
export JWT_ANALYZER_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
jwt-analyzer-api --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/dashboard` and paste the bearer token into the password field when prompted. Without `JWT_ANALYZER_API_TOKEN`, assessment endpoints on a loopback-only bind are unauthenticated, so do not change the bind host casually. The dashboard does not write the JWT or API token to local/session storage; results are held in page memory and rendered with `textContent` rather than interpreted as HTML.

## Remote binding

The server refuses non-loopback binds unless the operator explicitly opts in, provides a bearer token at least 32 characters long, and provides an exact Host allowlist. Example:

```bash
export JWT_ANALYZER_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
jwt-analyzer-api \
  --host 0.0.0.0 \
  --port 8765 \
  --allow-remote \
  --allowed-host analyzer.internal.example
```

Use remote mode only behind a TLS-terminating reverse proxy or on a private, access-controlled network. This service speaks HTTP; do not send bearer tokens over an untrusted network in clear text. Never use wildcard Host entries. The Host allowlist mitigates browser/DNS-rebinding access to the local service. Do not disable this check by customizing the app with a wildcard host list.

## Routes

### `GET /api/v1/health`

Returns a small health response containing `status` and the development version. It does not return configuration, environment variables or token data. This route is public for health checks.

### `POST /api/v1/inspect`

Request:

```json
{"token":"<compact JWT>"}
```

Returns the normalized `Assessment` schema used by the Python API, including `verification_status: "not_attempted"`. This endpoint parses and inspects only; it does not verify a signature or assert that a target is vulnerable.

### `POST /api/v1/verify`

Request:

```json
{
  "token": "<compact JWT>",
  "public_key": "<trusted PEM public key or public JWK>",
  "algorithms": ["RS256"],
  "issuer": "https://issuer.example",
  "audience": "example-api",
  "leeway": 0
}
```

`issuer`, `audience` and `leeway` are optional. The algorithm list is required, must be non-empty, and must contain supported asymmetric algorithms only. `public_key` is input material, not a URL; the service has no endpoint that fetches arbitrary JWKS URLs. A `verified` signature still does not establish application-specific authorization, tenant, scope or role policy.

## Limits and handling

- JWT compact strings are capped at the parser's 1 MiB limit; the service also bounds the HTTP request body (default roughly 2 MiB).
- Assessment endpoints are limited to 60 POST requests per client IP per minute per process by default.
- If `JWT_ANALYZER_API_TOKEN` is set, every assessment endpoint requires `Authorization: Bearer …`; comparison uses constant-time token comparison.
- `Host` headers are checked against an explicit allowlist; the default list is limited to local hosts used by the local server and tests.
- Security headers include `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a restrictive Content Security Policy. The dashboard uses a per-response script nonce.
- Request bodies and results are not persisted or logged by this module. Decoded claims can still contain sensitive values and are included in the direct response; treat assessment responses as sensitive data.
- No CORS middleware is enabled. The dashboard and API are served from the same origin.

## Error contract

| Status | Meaning |
|---|---|
| `400` | Invalid JSON or a non-object request body |
| `401` | Bearer token required or invalid when authentication is enabled |
| `413` | Request body or compact token exceeds its size limit |
| `422` | Missing/invalid request fields, malformed token structure, or invalid verification constraints |
| `429` | Per-client request rate limit exceeded |

A cryptographically invalid signature is a completed verification result and is returned as an assessment with `verification_status: "invalid"`; it is not treated as an HTTP transport failure.

## Known limitations before production use

The API/dashboard is an initial v2 slice. It still needs independent security review, dedicated slow-client and concurrency tests, complete OpenAPI/schema tooling, deployment guidance for TLS/proxy settings, and broader end-to-end/accessibility testing. Do not expose it directly to the public internet or use it to make authorization decisions.
