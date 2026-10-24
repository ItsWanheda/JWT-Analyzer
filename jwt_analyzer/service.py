"""Optional localhost-first HTTP service and same-origin dashboard for JWT Analyzer v2.

Install the ``service`` extra to use this module. Request tokens and decoded claims
are processed in memory only; the service does not persist assessments or log bodies.
"""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import secrets
import time
from threading import Lock
from typing import Any

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from starlette.types import ASGIApp, Receive, Scope, Send
except ImportError as exc:  # pragma: no cover - depends on optional install extra
    raise ImportError(
        "The JWT Analyzer HTTP service is optional; install it with `pip install jwt-analyzer[service]`."
    ) from exc

from core.parser import MAX_TOKEN_LENGTH

from . import __version__
from .api import inspect_token, verify_with_public_key


DEFAULT_MAX_REQUEST_BYTES = (2 * MAX_TOKEN_LENGTH) + 65_536
_DEFAULT_RATE_PER_MINUTE = 60


_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>JWT Analyzer · Local Dashboard</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; background: #0b1020; color: #eef2ff; }
    body { margin: 0; min-height: 100vh; }
    main { max-width: 980px; margin: 0 auto; padding: 2rem 1rem 4rem; }
    .eyebrow { color: #a5b4fc; font-size: .78rem; font-weight: 700; letter-spacing: .13em; text-transform: uppercase; }
    h1 { font-size: clamp(2rem, 5vw, 3.4rem); margin: .5rem 0; letter-spacing: -.04em; }
    p { color: #cbd5e1; line-height: 1.65; }
    .warning { border: 1px solid #854d0e; background: #422006; color: #fef3c7; padding: .9rem 1rem; border-radius: .8rem; }
    form { display: grid; gap: 1rem; margin-top: 1.5rem; }
    label { display: grid; gap: .45rem; color: #c7d2fe; font-weight: 650; }
    input, textarea { width: 100%; box-sizing: border-box; border: 1px solid #475569; border-radius: .65rem; background: #111827; color: #f8fafc; padding: .85rem; font: inherit; }
    textarea { min-height: 11rem; resize: vertical; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
    button { justify-self: start; border: 0; border-radius: .65rem; padding: .85rem 1.15rem; color: #0b1020; background: #a5b4fc; font: inherit; font-weight: 750; cursor: pointer; }
    button:focus-visible, input:focus-visible, textarea:focus-visible { outline: 3px solid #818cf8; outline-offset: 3px; }
    pre { background: #050816; border: 1px solid #334155; border-radius: .8rem; padding: 1rem; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; min-height: 5rem; }
    .section-title { margin: 2rem 0 .5rem; }
    small { color: #94a3b8; font-weight: 400; }
  </style>
</head>
<body>
  <main>
    <div class="eyebrow">JWT Analyzer · v2 development</div>
    <h1>Inspect before you trust.</h1>
    <p>Analyze token structure and review indicators locally. Inspection does not verify the signature and does not establish that a target application is vulnerable.</p>
    <div class="warning"><strong>Local handling:</strong> this page does not save tokens to browser storage. Do not use a shared browser or export decoded claims without reviewing sensitive values.</div>
    <form id="inspect-form">
      <label for="api-token">API bearer token <small>Required only if the service was started with authentication enabled.</small></label>
      <input id="api-token" type="password" autocomplete="off" spellcheck="false" aria-label="API bearer token">
      <label for="jwt">Compact JWT</label>
      <textarea id="jwt" required maxlength="1048576" autocomplete="off" spellcheck="false" placeholder="Paste a compact JWT here"></textarea>
      <button id="submit" type="submit">Inspect token</button>
    </form>
    <h2 class="section-title">Assessment output</h2>
    <pre id="result" role="status" aria-live="polite">No assessment yet.</pre>
  </main>
  <script nonce="__CSP_NONCE__">
    (() => {
      const form = document.querySelector("#inspect-form");
      const jwtInput = document.querySelector("#jwt");
      const apiTokenInput = document.querySelector("#api-token");
      const result = document.querySelector("#result");
      const submit = document.querySelector("#submit");
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const token = jwtInput.value;
        if (!token || token.length > 1048576) {
          result.textContent = "Enter a JWT no larger than 1 MiB.";
          return;
        }
        const headers = { "Content-Type": "application/json" };
        if (apiTokenInput.value) headers.Authorization = `Bearer ${apiTokenInput.value}`;
        submit.disabled = true;
        result.textContent = "Inspecting token…";
        try {
          const response = await fetch("/api/v1/inspect", {
            method: "POST",
            headers,
            cache: "no-store",
            body: JSON.stringify({ token })
          });
          const data = await response.json();
          result.textContent = JSON.stringify(data, null, 2);
        } catch (_) {
          result.textContent = "The request failed. Check that the local service is running and try again.";
        } finally {
          submit.disabled = false;
        }
      });
    })();
  </script>
</body>
</html>
"""


class _BodyTooLarge(Exception):
    """Internal signal that a streamed request body exceeded its configured cap."""


async def _send_json_error(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class MaxRequestBodyMiddleware:
    """Bound both declared and streamed HTTP request body size."""

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = 0
            if declared_length > self.max_body_bytes:
                await _send_json_error(send, 413, "Request body exceeds the configured size limit.")
                return

        received_bytes = 0
        response_started = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_bytes
            message = await receive()
            if message.get("type") == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_body_bytes:
                    raise _BodyTooLarge
            return message

        async def tracked_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _BodyTooLarge:
            if not response_started:
                await _send_json_error(send, 413, "Request body exceeds the configured size limit.")


class _WindowRateLimiter:
    """Small bounded in-memory fixed-window limiter; no IP data is persisted."""

    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._counts: dict[str, tuple[int, int]] = {}
        self._lock = Lock()

    def allow(self, client_key: str) -> bool:
        window = int(time.monotonic() // self.window_seconds)
        with self._lock:
            if len(self._counts) > 4096:
                self._counts = {
                    key: value for key, value in self._counts.items() if value[0] >= window
                }
            current = self._counts.get(client_key)
            if current is None or current[0] != window:
                self._counts[client_key] = (window, 1)
                return True
            if current[1] >= self.limit:
                return False
            self._counts[client_key] = (window, current[1] + 1)
            return True


class RequestRateLimitMiddleware:
    """Apply a per-client fixed-window limit to assessment endpoints."""

    def __init__(self, app: ASGIApp, requests_per_minute: int) -> None:
        self.app = app
        self.limiter = _WindowRateLimiter(requests_per_minute)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http":
            path = scope.get("path", "")
            method = scope.get("method", "GET").upper()
            if method == "POST" and path in {"/api/v1/inspect", "/api/v1/verify"}:
                client = scope.get("client")
                client_key = client[0] if client else "unknown"
                if not self.limiter.allow(client_key):
                    await _send_json_error(send, 429, "Request rate limit exceeded; retry in a later window.")
                    return
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Set safe defaults without overriding route-specific dashboard CSP."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def secure_send(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers}
                defaults = [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'"),
                ]
                headers.extend((name, value) for name, value in defaults if name not in existing)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, secure_send)


def _auth_dependency(api_token: str | None):
    async def require_bearer_token(
        authorization: str | None = Header(default=None),
    ) -> None:
        if api_token is None:
            return
        scheme, separator, supplied = (authorization or "").partition(" ")
        if not separator or scheme.lower() != "bearer" or not supplied:
            raise HTTPException(
                status_code=401,
                detail="A bearer token is required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not hmac.compare_digest(supplied, api_token):
            raise HTTPException(
                status_code=401,
                detail="Bearer token is invalid.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return require_bearer_token


async def _read_json_object(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")
    return body


def create_app(
    *,
    api_token: str | None = None,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    requests_per_minute: int = _DEFAULT_RATE_PER_MINUTE,
) -> FastAPI:
    """Create the optional HTTP API; tokens are processed in memory only.

    Pass ``api_token`` to require bearer authentication for every assessment
    endpoint. The command-line server requires both ``--allow-remote`` and a
    token for non-loopback binds.
    """
    if api_token is not None and not api_token.strip():
        raise ValueError("api_token must not be empty when supplied")
    if isinstance(max_request_bytes, bool) or not isinstance(max_request_bytes, int) or max_request_bytes < 1:
        raise ValueError("max_request_bytes must be a positive integer")
    if isinstance(requests_per_minute, bool) or not isinstance(requests_per_minute, int) or requests_per_minute < 1:
        raise ValueError("requests_per_minute must be a positive integer")

    app = FastAPI(
        title="JWT Analyzer API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    authorize = _auth_dependency(api_token)
    app.add_middleware(MaxRequestBodyMiddleware, max_body_bytes=max_request_bytes)
    app.add_middleware(RequestRateLimitMiddleware, requests_per_minute=requests_per_minute)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/api/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/api/v1/inspect")
    async def inspect_endpoint(
        request: Request,
        _auth: Any = Depends(authorize),
    ) -> JSONResponse:
        body = await _read_json_object(request)
        token = body.get("token")
        if not isinstance(token, str) or not token.strip():
            raise HTTPException(status_code=422, detail="token must be a non-empty string.")
        if len(token) > MAX_TOKEN_LENGTH:
            raise HTTPException(status_code=413, detail="JWT exceeds the configured token-size limit.")
        try:
            assessment = inspect_token(token)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="JWT structure or claims are invalid.") from exc
        return JSONResponse(assessment.to_dict())

    @app.post("/api/v1/verify")
    async def verify_endpoint(
        request: Request,
        _auth: Any = Depends(authorize),
    ) -> JSONResponse:
        body = await _read_json_object(request)
        token = body.get("token")
        key_content = body.get("public_key")
        algorithms = body.get("algorithms")
        if not isinstance(token, str) or not token.strip():
            raise HTTPException(status_code=422, detail="token must be a non-empty string.")
        if len(token) > MAX_TOKEN_LENGTH:
            raise HTTPException(status_code=413, detail="JWT exceeds the configured token-size limit.")
        if not isinstance(key_content, str) or not key_content.strip():
            raise HTTPException(status_code=422, detail="public_key must contain a trusted PEM public key or public JWK.")
        if not isinstance(algorithms, list):
            raise HTTPException(status_code=422, detail="algorithms must be a JSON array of allowed asymmetric algorithms.")
        try:
            assessment = verify_with_public_key(
                token,
                key_content,
                algorithms=algorithms,
                issuer=body.get("issuer"),
                audience=body.get("audience"),
                leeway=body.get("leeway", 0),
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Invalid token or verification options.") from exc
        return JSONResponse(assessment.to_dict())

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        nonce = secrets.token_urlsafe(18)
        html = _DASHBOARD_HTML.replace("__CSP_NONCE__", nonce)
        csp = (
            "default-src 'self'; "
            f"script-src 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self'; "
            "frame-ancestors 'none'; object-src 'none'; base-uri 'none'"
        )
        return HTMLResponse(html, headers={"Content-Security-Policy": csp, "Cache-Control": "no-store"})

    return app


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> None:
    """Run the service with local-only defaults and explicit remote opt-in."""
    parser = argparse.ArgumentParser(description="Run the optional JWT Analyzer HTTP service.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765).")
    parser.add_argument(
        "--api-token",
        default=os.environ.get("JWT_ANALYZER_API_TOKEN"),
        help="Bearer token; may also be supplied via JWT_ANALYZER_API_TOKEN.",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Explicitly permit a non-loopback bind; requires a bearer token.",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    loopback = _is_loopback_host(args.host)
    if not loopback and not args.allow_remote:
        parser.error("Non-loopback binds require --allow-remote.")
    if not loopback and not args.api_token:
        parser.error("Non-loopback binds require --api-token or JWT_ANALYZER_API_TOKEN.")
    if args.api_token is not None and not args.api_token.strip():
        parser.error("--api-token must not be empty.")

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on optional install extra
        parser.error("Install the optional service dependencies with `pip install jwt-analyzer[service]`.")
        raise SystemExit(2) from exc
    uvicorn.run(
        create_app(api_token=args.api_token),
        host=args.host,
        port=args.port,
        access_log=False,
        server_header=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
