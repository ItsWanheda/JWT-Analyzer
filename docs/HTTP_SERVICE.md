# Optional HTTP Service and Dashboard

**Status:** unreleased v2 development functionality. The service is an opt-in interface over the shared assessment engine. It is not an authentication server, an authorization decision point, or a remote JWKS resolver.

## Install and run locally

The HTTP service is an optional dependency group; the default CLI and Python API do not import FastAPI or Pydantic.

Install the service extra in an isolated environment:

    python -m pip install -e ".[service]"

The service binds to loopback by default. Authentication can be enabled locally by exporting a bearer token before startup:

    export JWT_ANALYZER_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    jwt-analyzer-api --host 127.0.0.1 --port 8765

Open http://127.0.0.1:8765/dashboard and paste the bearer token into the password field when prompted. Configured bearer tokens must contain at least 32 characters. Without JWT_ANALYZER_API_TOKEN, assessment routes on a loopback-only bind are unauthenticated; do not change the bind host casually.

The dashboard does not write the JWT or API token to local/session storage. It renders response data with textContent, uses a per-response script nonce, and sends requests to the same origin.

## Remote binding

The CLI refuses non-loopback binds unless all of these are explicit:

1. --allow-remote
2. A bearer token of at least 32 characters, passed with --api-token or JWT_ANALYZER_API_TOKEN
3. At least one exact --allowed-host value; wildcard entries are rejected

Example:

    export JWT_ANALYZER_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    jwt-analyzer-api \
      --host 0.0.0.0 \
      --port 8765 \
      --allow-remote \
      --allowed-host analyzer.internal.example

Use remote mode only behind a TLS-terminating reverse proxy or on a private, access-controlled network. This service speaks HTTP; never send bearer tokens over an untrusted network in clear text. Configure TLS, external rate limiting, request buffering and connection limits at the reverse proxy. Do not use wildcard Host entries.

The service disables Uvicorn proxy-header trust by default. This prevents untrusted X-Forwarded-For values from being used as rate-limit identities. When deployed behind a proxy, the service sees the proxy peer address, so all users behind the same proxy share the service-level per-client bucket; apply per-client rate limiting at the trusted proxy as well.

The Host allowlist mitigates browser/DNS-rebinding access to the local service. Do not disable it by passing a wildcard host list to create_app().

## OpenAPI and versioned contract

The generated OpenAPI document is served locally at GET /api/v1/openapi.json. It describes the versioned request fields, limits, response models, routes, and error statuses. There is no third-party hosted documentation JavaScript or CDN dependency.

Request bodies are strict objects: undeclared fields are rejected. inspect accepts a compact JWT string. verify accepts a compact JWT, an inline PEM public key or one inline public JWK, an explicit asymmetric algorithm allowlist, and optional issuer/audience/leeway constraints. Public-key text is capped at 64 KiB; JWTs are capped at the parser's 1 MiB limit.

## Routes

### GET /api/v1/health

Compatibility health response containing status and the development version. This route is public and does not return configuration, environment variables or token data.

### GET /api/v1/health/live

Liveness probe. Returns status: alive while the process is serving requests.

### GET /api/v1/health/ready

Readiness probe. Returns status: ready while the application lifecycle is active; it returns HTTP 503 during shutdown. The service has no external runtime dependency that needs to be queried for readiness.

### POST /api/v1/inspect

Request:

    {"token":"<compact JWT>"}

Returns the normalized Assessment v1.1 response, including verification_status: "not_attempted". This endpoint parses and inspects only; it does not verify a signature or assert that a target is vulnerable.

### POST /api/v1/verify

Request:

    {
      "token": "<compact JWT>",
      "public_key": "<trusted PEM public key or one public JWK JSON object>",
      "algorithms": ["RS256"],
      "issuer": "https://issuer.example",
      "audience": "example-api",
      "leeway": 0
    }

issuer, audience and leeway are optional. The algorithm list is required, must be non-empty, unique, and contain supported asymmetric algorithms only. A verified signature still does not establish application-specific authorization, tenant, scope or role policy.

**SSRF boundary:** public_key is key material, not a URL. This service does not expose a JWKS URL, jku, x5u, or other remote-key fetch option. It accepts a single inline PEM public key or single public JWK only; JWK Sets and JWK members outside the supported inline-key allowlist are rejected. No API route performs outbound HTTP, DNS resolution, redirects, or proxy access. The contract rejects unexpected request properties such as jwks_url.

### GET /api/v1/openapi.json

Returns the generated OpenAPI contract. It is safe to expose alongside the API because it contains schemas and route metadata, not secrets or runtime configuration.

## Limits and handling

| Control | Default | Bound / behavior |
|---|---:|---|
| Compact JWT | 1 MiB | Parser limit; a larger token returns HTTP 413 |
| Public key material | 64 KiB | Single inline PEM or JWK only |
| HTTP body | Approximately 2 MiB | Configurable up to 8 MiB; declared and streamed bodies are bounded |
| Request lifetime | 15 seconds | Configurable from 0.05 to 120 seconds; includes slow body reads |
| Concurrent assessments | 4 | Configurable from 1 to 32; CPU-bound work is dispatched to a bounded thread-pool path |
| Assessment rate | 60 POST requests/client/minute | In-memory per process; limiter state is capped at 4,096 client keys |
| Bearer token | Disabled on loopback unless configured | Required for every assessment route when configured; minimum 32 characters |

Additional handling:

- Host is checked against the exact allowlist; the loopback defaults include 127.0.0.1, localhost and [::1].
- Security headers include Cache-Control: no-store, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer, same-origin resource policy, and a restrictive Content Security Policy. The dashboard uses a per-response script nonce.
- No CORS middleware is enabled. The dashboard and API are same-origin.
- Server-generated X-Request-ID values correlate responses with structured, body-free logs. Logs include route, method, status, duration and exception type only; JWTs, claims, public-key contents and bearer credentials are not logged.
- Request bodies, claims and assessments are not persisted by this module. Decoded claims can still contain sensitive values and are present in direct responses; treat assessment responses as sensitive data.
- Startup marks the application ready; shutdown clears readiness. Uvicorn keep-alive and graceful-shutdown windows are bounded.

A request timeout bounds how long the HTTP request waits. It is not a guarantee that an already-running native or synchronous operation can be forcibly interrupted. Input limits and the concurrency semaphore bound the amount of in-flight work; reverse-proxy timeouts and resource controls remain necessary for remote deployments.

## Error contract

Errors use a stable JSON envelope:

    {
      "error": {
        "code": "invalid_request",
        "message": "Request body does not match the documented API schema.",
        "request_id": "server-generated-id"
      }
    }

| Status | Error code examples | Meaning |
|---|---|---|
| 400 | invalid_json, invalid_content_length | Invalid JSON or malformed Content-Length |
| 401 | unauthorized | Bearer token required or invalid |
| 408 | request_timeout | Request exceeded the configured time limit |
| 413 | request_too_large, payload_too_large | Request body, JWT or key field exceeds its limit |
| 422 | invalid_request, http_error | Schema, token structure, inline key or verification options are invalid |
| 429 | rate_limited | Per-client request rate limit exceeded |
| 500 | internal_error | Unexpected error; internal details and request data are not returned |
| 503 | http_error | Service is not ready |

A cryptographically invalid signature is a completed verification result and is returned as an assessment with verification_status: invalid; it is not an HTTP transport failure.

## Operator checklist

Before remote use, terminate TLS, configure upstream request and connection limits, set a high-entropy bearer token through a secret manager, specify exact Host values, and apply a trusted edge rate limit. Keep the service behind a private network or authenticated gateway. Do not upload raw request logs or unredacted assessment responses to shared systems.

This optional service is an initial v2 development interface. It still requires independent security review and deployment-specific testing before public production exposure. It must not be used as an authentication server or as the sole basis for authorization decisions.
