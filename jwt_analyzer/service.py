"""Optional loopback-first HTTP API and same-origin dashboard for JWT Analyzer v2.

The service is deliberately not a remote JWKS client. Verification accepts a
caller-supplied PEM public key or a single inline public JWK; it never fetches
URLs. Request data is processed in memory and is not persisted or logged.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import ipaddress
import json
import logging
import os
import secrets
import sys
import time
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from threading import Lock
from typing import Any, Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel, Field, StrictBool, StrictInt, StrictStr, validator
    from starlette.concurrency import run_in_threadpool
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    from starlette.types import ASGIApp, Message, Receive, Scope, Send
except ImportError as exc:  # pragma: no cover - depends on optional install extra
    if sys.version_info < (3, 10):
        raise ImportError(
            "The optional HTTP service requires Python 3.10 or newer to use "
            "security-patched FastAPI/Starlette releases. The core CLI and Python API "
            "continue to support Python 3.9."
        ) from exc
    raise ImportError(
        "The JWT Analyzer HTTP service is optional; install it with "
        "pip install jwt-analyzer[service]."
    ) from exc

if sys.version_info < (3, 10):  # pragma: no cover - framework compatibility guard
    raise RuntimeError(
        "The optional HTTP service requires Python 3.10 or newer to use "
        "security-patched FastAPI/Starlette releases. The core CLI and Python API "
        "continue to support Python 3.9."
    )

from core.parser import MAX_TOKEN_LENGTH
from core.strict_json import strict_json_loads
from core.verification import DEFAULT_ASYMMETRIC_ALGORITHMS, MAX_PUBLIC_KEY_BYTES
from jwt_analyzer import ReportFormat, __version__, render_report
from jwt_analyzer.api import inspect_token, verify_with_public_key
from jwt_analyzer.models import Assessment

DEFAULT_MAX_REQUEST_BYTES = (2 * MAX_TOKEN_LENGTH) + 65_536
_DEFAULT_RATE_PER_MINUTE = 60
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 15.0
_DEFAULT_MAX_CONCURRENT_ASSESSMENTS = 4
_MAX_RATE_LIMITER_CLIENTS = 4096
_MAX_PORT = 65535
_REMOTE_TOKEN_MIN_LENGTH = 32
_MAX_REQUEST_BYTES = 8 * 1024 * 1024
_MAX_CONCURRENT_ASSESSMENTS = 32
_MAX_REQUEST_TIMEOUT_SECONDS = 120.0
_LOGGER = logging.getLogger("jwt_analyzer.service")
_ALLOWED_JWK_MEMBERS = frozenset({"kty", "use", "key_ops", "alg", "kid", "n", "e", "crv", "x", "y"})


class InspectRequest(BaseModel):
    """Versioned inspect request contract."""

    token: StrictStr = Field(
        min_length=1,
        max_length=MAX_TOKEN_LENGTH,
        description="Compact serialized JWT. Inspection does not verify its signature.",
    )

    class Config:
        extra = "forbid"


class VerifyRequest(BaseModel):
    """Versioned verification request contract."""

    token: StrictStr = Field(min_length=1, max_length=MAX_TOKEN_LENGTH)
    public_key: StrictStr = Field(
        min_length=1,
        max_length=MAX_PUBLIC_KEY_BYTES,
        description="Inline PEM public key or a single public JWK JSON object; URLs are forbidden.",
    )
    algorithms: list[StrictStr] = Field(
        description="Explicit allowlist of supported asymmetric JWT algorithms.",
    )

    @validator("algorithms")
    def validate_algorithms(cls, value: list[str]) -> list[str]:  # noqa: N805
        """Keep list bounds compatible with Pydantic v1 and v2."""
        if not 1 <= len(value) <= len(DEFAULT_ASYMMETRIC_ALGORITHMS):
            raise ValueError(
                "Algorithm allowlist must contain between 1 and the supported maximum."
            )
        return value

    issuer: Optional[StrictStr] = Field(default=None, max_length=2048)  # noqa: UP045
    audience: Optional[StrictStr] = Field(default=None, max_length=2048)  # noqa: UP045
    leeway: StrictInt = Field(default=0, ge=0, le=86_400)

    class Config:
        extra = "forbid"


class ReportRequest(BaseModel):
    """Validated request for a redacted-by-default report export."""

    assessment: dict[str, Any]
    format: StrictStr = Field(min_length=1, max_length=16)
    include_sensitive: StrictBool = False

    class Config:
        extra = "forbid"


class HealthResponse(BaseModel):
    status: str
    version: str


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None  # noqa: UP045


class ErrorResponse(BaseModel):
    error: ErrorDetail


_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>JWT Analyzer · Assessment Dashboard</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; background: #0b1020; color: #eef2ff; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; }
    main { max-width: 1100px; margin: 0 auto; padding: 2rem 1rem 4rem; }
    .eyebrow { color: #a5b4fc; font-size: .78rem; font-weight: 700; letter-spacing: .13em; text-transform: uppercase; }
    h1 { font-size: clamp(2rem, 5vw, 3.2rem); margin: .5rem 0; letter-spacing: -.04em; }
    h2 { margin: 0 0 .7rem; font-size: 1.2rem; }
    p { color: #cbd5e1; line-height: 1.65; }
    .warning { border: 1px solid #854d0e; background: #422006; color: #fef3c7; padding: .9rem 1rem; border-radius: .8rem; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; margin-top: 1.25rem; }
    section { min-width: 0; border: 1px solid #334155; background: #111827; border-radius: .9rem; padding: 1rem; }
    label { display: grid; gap: .4rem; margin: .75rem 0; color: #c7d2fe; font-weight: 650; }
    small { color: #94a3b8; font-weight: 400; line-height: 1.5; }
    input, textarea, select { width: 100%; border: 1px solid #475569; border-radius: .55rem; background: #0b1020; color: #f8fafc; padding: .75rem; font: inherit; }
    textarea { min-height: 8rem; resize: vertical; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
    button { border: 0; border-radius: .55rem; padding: .75rem 1rem; color: #0b1020; background: #a5b4fc; font: inherit; font-weight: 750; cursor: pointer; }
    button:disabled { opacity: .55; cursor: wait; }
    button:focus-visible, input:focus-visible, textarea:focus-visible, select:focus-visible { outline: 3px solid #818cf8; outline-offset: 3px; }
    .actions { display: flex; flex-wrap: wrap; gap: .65rem; align-items: center; margin-top: .8rem; }
    .check { display: flex; grid-template-columns: auto 1fr; align-items: center; gap: .55rem; }
    .check input { width: auto; }
    pre { background: #050816; border: 1px solid #334155; border-radius: .8rem; padding: 1rem; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; min-height: 7rem; }
    #status { min-height: 1.5rem; color: #c7d2fe; }
    .wide { grid-column: 1 / -1; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } .wide { grid-column: auto; } }
  </style>
</head>
<body>
  <main>
    <div class="eyebrow">JWT Analyzer · v2 development</div>
    <h1>Inspect. Verify. Understand.</h1>
    <p>Inspecting decodes untrusted data. Verification is a separate operation and requires an explicit trusted public key and algorithm allowlist. Neither operation authorizes access to an application.</p>
    <div class="warning"><strong>Local handling:</strong> inputs and results stay in page memory only. They are not saved to browser storage. Reports are redacted by default; only enable sensitive exports when you have a controlled reason.</div>

    <section aria-labelledby="auth-heading">
      <h2 id="auth-heading">Service authentication</h2>
      <label for="api-token">API bearer token <small>Only needed when service authentication is enabled. It is sent in the Authorization header and is not stored.</small></label>
      <input id="api-token" type="password" autocomplete="off" spellcheck="false">
    </section>

    <div class="grid">
      <section aria-labelledby="inspect-heading">
        <h2 id="inspect-heading">1. Inspect a token</h2>
        <form id="inspect-form" method="post">
          <label for="jwt-file">Load JWT from a local file <small>Read locally in this browser; the file is not uploaded until you submit the inspection request.</small></label>
          <input id="jwt-file" type="file" accept=".jwt,.txt,text/plain">
          <label for="jwt">Compact JWT</label>
          <textarea id="jwt" required maxlength="1048576" autocomplete="off" spellcheck="false" placeholder="Paste a compact JWT"></textarea>
          <button id="inspect-submit" type="submit">Inspect token</button>
        </form>
        <small>Inspection does not verify signatures, issuer, audience, or remote verifier behavior.</small>
      </section>

      <section aria-labelledby="verify-heading">
        <h2 id="verify-heading">2. Verify a signature</h2>
        <form id="verify-form" method="post">
          <label for="verify-jwt-file">Load JWT from a local file <small>Read locally in this browser; the file is not uploaded until you submit verification.</small></label>
          <input id="verify-jwt-file" type="file" accept=".jwt,.txt,text/plain">
          <label for="verify-jwt">Compact JWT</label>
          <textarea id="verify-jwt" required maxlength="1048576" autocomplete="off" spellcheck="false" placeholder="Paste the JWT to verify"></textarea>
          <label for="public-key">Inline public key (PEM or one public JWK)</label>
          <textarea id="public-key" required maxlength="65536" autocomplete="off" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea>
          <label for="algorithms">Allowed asymmetric algorithms <small>Comma-separated; never inferred from the token header.</small></label>
          <input id="algorithms" value="RS256" autocomplete="off">
          <label for="issuer">Expected issuer (optional)</label>
          <input id="issuer" autocomplete="off">
          <label for="audience">Expected audience (optional)</label>
          <input id="audience" autocomplete="off">
          <label for="leeway">Clock leeway in seconds</label>
          <input id="leeway" type="number" min="0" max="86400" value="0">
          <button id="verify-submit" type="submit">Verify signature</button>
        </form>
        <small>No remote JWKS, URL-based key lookup, or arbitrary network fetch is supported.</small>
      </section>

      <section class="wide" aria-labelledby="result-heading">
        <h2 id="result-heading">Assessment result</h2>
        <p id="status" role="status" aria-live="polite">No assessment yet.</p>
        <pre id="result" tabindex="0" aria-label="Redacted assessment result">No assessment yet.</pre>
        <div class="actions">
          <label for="report-format">Export format</label>
          <select id="report-format" aria-label="Report format">
            <option value="json">JSON</option>
            <option value="html">HTML</option>
            <option value="sarif">SARIF</option>
          </select>
          <label class="check" for="include-sensitive">
            <input id="include-sensitive" type="checkbox">
            Include sensitive values (explicit opt-in)
          </label>
          <button id="export-submit" type="button" disabled>Export report</button>
        </div>
        <small>Exports use the shared, schema-validated report engine. Redaction remains enabled unless the checkbox is deliberately selected.</small>
      </section>

      <section class="wide" aria-labelledby="compare-heading">
        <h2 id="compare-heading">3. Compare assessments</h2>
        <p>Paste two assessment JSON objects or JSON report envelopes. Comparison is performed locally in this page.</p>
        <div class="grid">
          <label for="compare-a">Earlier assessment<textarea id="compare-a" spellcheck="false" placeholder="Paste assessment A"></textarea></label>
          <label for="compare-b">Later assessment<textarea id="compare-b" spellcheck="false" placeholder="Paste assessment B"></textarea></label>
        </div>
        <button id="compare-submit" type="button">Compare findings</button>
        <pre id="comparison" tabindex="0" aria-live="polite">No comparison yet.</pre>
      </section>
    </div>
  </main>

  <script nonce="__CSP_NONCE__">
    (() => {
      "use strict";
      const byId = (id) => document.getElementById(id);
      const apiToken = byId("api-token");
      const result = byId("result");
      const status = byId("status");
      const exportButton = byId("export-submit");
      let lastAssessment = null;

      function authHeaders() {
        const headers = { "Content-Type": "application/json" };
        if (apiToken.value) headers.Authorization = "Bearer " + apiToken.value;
        return headers;
      }

      function attachLocalFile(fileInputId, textAreaId) {
        byId(fileInputId).addEventListener("change", async () => {
          const input = byId(fileInputId);
          const file = input.files && input.files[0];
          if (!file) return;
          if (file.size > 1048576) {
            status.textContent = "Selected file exceeds the 1 MiB JWT limit.";
            input.value = "";
            return;
          }
          try {
            const contents = await file.text();
            if (contents.length > 1048576) throw new Error("file_too_large");
            byId(textAreaId).value = contents.trim();
            status.textContent = "File read locally. Submit the form to send the token for assessment.";
          } catch (_) {
            status.textContent = "Could not read the selected JWT file.";
            input.value = "";
          }
        });
      }

      attachLocalFile("jwt-file", "jwt");
      attachLocalFile("verify-jwt-file", "verify-jwt");

      async function postJson(path, payload) {
        const response = await fetch(path, {
          method: "POST",
          headers: authHeaders(),
          cache: "no-store",
          credentials: "same-origin",
          body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) {
          const message = data && data.error && data.error.message;
          throw new Error(message || "The request could not be completed.");
        }
        return data;
      }

      async function showAssessment(assessment, operation) {
        lastAssessment = assessment;
        exportButton.disabled = false;
        const safeReport = await postJson("/api/v1/report", {
          assessment: assessment,
          format: "json",
          include_sensitive: false
        });
        result.textContent = safeReport.content;
        status.textContent = operation + " completed. Displayed assessment is redacted.";
      }

      byId("inspect-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const token = byId("jwt").value;
        if (!token || token.length > 1048576) {
          status.textContent = "Enter a JWT no larger than 1 MiB.";
          return;
        }
        const button = byId("inspect-submit");
        button.disabled = true;
        status.textContent = "Inspecting…";
        try {
          const assessment = await postJson("/api/v1/inspect", { token: token });
          await showAssessment(assessment, "Inspection");
        } catch (_) {
          lastAssessment = null;
          exportButton.disabled = true;
          status.textContent = "Inspection failed. Check the input and service status.";
          result.textContent = "No assessment was displayed.";
        } finally {
          button.disabled = false;
        }
      });

      byId("verify-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = byId("verify-submit");
        const algorithms = byId("algorithms").value.split(",").map((value) => value.trim()).filter(Boolean);
        const leeway = Number(byId("leeway").value);
        if (!Number.isInteger(leeway) || leeway < 0 || leeway > 86400) {
          status.textContent = "Clock leeway must be an integer from 0 to 86400.";
          return;
        }
        button.disabled = true;
        status.textContent = "Verifying with the supplied public key…";
        try {
          const payload = {
            token: byId("verify-jwt").value,
            public_key: byId("public-key").value,
            algorithms: algorithms,
            leeway: leeway
          };
          if (byId("issuer").value) payload.issuer = byId("issuer").value;
          if (byId("audience").value) payload.audience = byId("audience").value;
          const assessment = await postJson("/api/v1/verify", payload);
          await showAssessment(assessment, "Signature verification");
        } catch (_) {
          lastAssessment = null;
          exportButton.disabled = true;
          status.textContent = "Verification failed. Check the key, algorithm allowlist, and token.";
          result.textContent = "No assessment was displayed.";
        } finally {
          button.disabled = false;
        }
      });

      exportButton.addEventListener("click", async () => {
        if (!lastAssessment) return;
        exportButton.disabled = true;
        status.textContent = "Preparing report…";
        try {
          const format = byId("report-format").value;
          const includeSensitive = byId("include-sensitive").checked;
          const report = await postJson("/api/v1/report", {
            assessment: lastAssessment,
            format: format,
            include_sensitive: includeSensitive
          });
          const mime = format === "html" ? "text/html" : "application/json";
          const blob = new Blob([report.content], { type: mime + ";charset=utf-8" });
          const objectUrl = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = objectUrl;
          link.download = "jwt-assessment." + (format === "sarif" ? "sarif" : format);
          document.body.appendChild(link);
          link.click();
          link.remove();
          URL.revokeObjectURL(objectUrl);
          status.textContent = includeSensitive
            ? "Report exported with sensitive values by explicit opt-in."
            : "Redacted report exported.";
        } catch (_) {
          status.textContent = "Report export failed. No file was created.";
        } finally {
          exportButton.disabled = false;
        }
      });

      function unwrapAssessment(value) {
        return value && value.assessment ? value.assessment : value;
      }

      function stableStringify(value) {
        if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
        if (value && typeof value === "object") {
          return "{" + Object.keys(value).sort().map((key) =>
            JSON.stringify(key) + ":" + stableStringify(value[key])
          ).join(",") + "}";
        }
        return JSON.stringify(value);
      }

      byId("compare-submit").addEventListener("click", async () => {
        const output = byId("comparison");
        try {
          const beforeInput = unwrapAssessment(JSON.parse(byId("compare-a").value));
          const afterInput = unwrapAssessment(JSON.parse(byId("compare-b").value));
          const beforeReport = await postJson("/api/v1/report", {
            assessment: beforeInput, format: "json", include_sensitive: false
          });
          const afterReport = await postJson("/api/v1/report", {
            assessment: afterInput, format: "json", include_sensitive: false
          });
          const before = JSON.parse(beforeReport.content).assessment;
          const after = JSON.parse(afterReport.content).assessment;
          if (!Array.isArray(before.findings) || !Array.isArray(after.findings)) {
            throw new Error("Both inputs must contain a findings array.");
          }
          const left = new Map(before.findings.map((finding) => [finding.id, finding]));
          const right = new Map(after.findings.map((finding) => [finding.id, finding]));
          const added = [];
          const removed = [];
          const changed = [];
          for (const [id, finding] of right) {
            if (!left.has(id)) added.push({ id: id, severity: finding.severity, title: finding.title });
            else if (stableStringify(left.get(id)) !== stableStringify(finding)) {
              changed.push({ id: id, before: left.get(id), after: finding });
            }
          }
          for (const [id, finding] of left) {
            if (!right.has(id)) removed.push({ id: id, severity: finding.severity, title: finding.title });
          }
          output.textContent = JSON.stringify({
            added: added,
            removed: removed,
            changed: changed,
            summary: { added: added.length, removed: removed.length, changed: changed.length }
          }, null, 2);
        } catch (_) {
          output.textContent = "Comparison failed. Supply two valid assessment JSON objects.";
        }
      });
    })();
  </script>
</body>
</html>
"""


async def _send_json_error(
    send: Send,
    status: int,
    code: str,
    message: str,
    request_id: Optional[str] = None,  # noqa: UP045 - PEP 604 union syntax is not runtime-safe for Pydantic v1
) -> None:
    body = json.dumps(
        {
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")
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


class _BodyTooLargeError(Exception):
    """Internal signal that a streamed request body exceeded its configured cap."""


class MaxRequestBodyMiddleware:
    """Bound declared and streamed request bodies before JSON parsing."""

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        lengths = [
            value for name, value in scope.get("headers", []) if name.lower() == b"content-length"
        ]
        if len(lengths) > 1:
            await _send_json_error(
                send,
                400,
                "invalid_content_length",
                "Invalid Content-Length header.",
                scope.get("state", {}).get("request_id"),
            )
            return
        if lengths:
            raw_length = lengths[0]
            if not raw_length.isdigit():
                await _send_json_error(
                    send,
                    400,
                    "invalid_content_length",
                    "Invalid Content-Length header.",
                    scope.get("state", {}).get("request_id"),
                )
                return
            if int(raw_length) > self.max_body_bytes:
                await _send_json_error(
                    send,
                    413,
                    "request_too_large",
                    "Request body exceeds the configured size limit.",
                    scope.get("state", {}).get("request_id"),
                )
                return

        received_bytes = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message.get("type") == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_body_bytes:
                    raise _BodyTooLargeError
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _BodyTooLargeError:
            if not response_started:
                await _send_json_error(
                    send,
                    413,
                    "request_too_large",
                    "Request body exceeds the configured size limit.",
                    scope.get("state", {}).get("request_id"),
                )


class _WindowRateLimiter:
    """Small bounded in-memory fixed-window limiter; client data is not persisted."""

    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._counts: dict[str, tuple[int, int]] = {}
        self._lock = Lock()

    def allow(self, client_key: str) -> bool:
        window = int(time.monotonic() // self.window_seconds)
        with self._lock:
            current = self._counts.get(client_key)
            if current is None and len(self._counts) >= _MAX_RATE_LIMITER_CLIENTS:
                self._counts = {
                    key: value for key, value in self._counts.items() if value[0] >= window
                }
                if len(self._counts) >= _MAX_RATE_LIMITER_CLIENTS:
                    return False
                current = self._counts.get(client_key)
            if current is None or current[0] != window:
                self._counts[client_key] = (window, 1)
                return True
            if current[1] >= self.limit:
                return False
            self._counts[client_key] = (window, current[1] + 1)
            return True


class RequestRateLimitMiddleware:
    """Apply a per-peer fixed-window limit to assessment routes."""

    def __init__(self, app: ASGIApp, requests_per_minute: int) -> None:
        self.app = app
        self.limiter = _WindowRateLimiter(requests_per_minute)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http":
            path = scope.get("path", "")
            method = scope.get("method", "GET").upper()
            if method == "POST" and path in {"/api/v1/inspect", "/api/v1/verify", "/api/v1/report"}:
                client = scope.get("client")
                client_key = str(client[0]) if client else "unknown"
                if not self.limiter.allow(client_key):
                    await _send_json_error(
                        send,
                        429,
                        "rate_limited",
                        "Request rate limit exceeded; retry in a later window.",
                        scope.get("state", {}).get("request_id"),
                    )
                    return
        await self.app(scope, receive, send)


class RequestTimeoutMiddleware:
    """Bound total request lifetime, including slow request-body reads."""

    def __init__(self, app: ASGIApp, timeout_seconds: float) -> None:
        self.app = app
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await asyncio.wait_for(
                self.app(scope, receive, tracked_send),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            if not response_started:
                await _send_json_error(
                    send,
                    408,
                    "request_timeout",
                    "Request exceeded the configured time limit.",
                    scope.get("state", {}).get("request_id"),
                )


class RequestContextMiddleware:
    """Attach a server-generated request ID and emit body-free structured logs."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request_id = secrets.token_hex(12)
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.monotonic()
        status_code = 500

        async def tracked_send(message: Message) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 500))
                headers = list(message.get("headers", []))
                if not any(name.lower() == b"x-request-id" for name, _ in headers):
                    headers.append((b"x-request-id", request_id.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        finally:
            route = scope.get("route")
            route_path = getattr(route, "path", scope.get("path", "/"))
            record = {
                "event": "http_request",
                "request_id": request_id,
                "method": scope.get("method", "GET"),
                "route": route_path,
                "status_code": status_code,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }
            _LOGGER.info(json.dumps(record, separators=(",", ":")))


class SafeErrorMiddleware:
    """Convert unexpected application failures into redacted JSON responses."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        response_started = False

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        except Exception as exc:
            state = scope.get("state", {})
            request_id = state.get("request_id")
            _LOGGER.error(  # noqa: TRY400 - intentionally omit exception/traceback text
                json.dumps(
                    {
                        "event": "request_failed",
                        "request_id": request_id,
                        "exception_type": type(exc).__name__,
                    },
                    separators=(",", ":"),
                )
            )
            if not response_started:
                body = json.dumps(
                    {
                        "error": {
                            "code": "internal_error",
                            "message": "An internal error occurred. No request data was recorded.",
                            "request_id": request_id,
                        }
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 500,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii")),
                            (b"cache-control", b"no-store"),
                            (b"x-content-type-options", b"nosniff"),
                            (b"x-frame-options", b"DENY"),
                            (b"referrer-policy", b"no-referrer"),
                            (b"x-request-id", str(request_id or "").encode("ascii")),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    """Set safe response headers without overriding route-specific dashboard CSP."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def secure_send(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers}
                defaults = [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cross-origin-resource-policy", b"same-origin"),
                    (
                        b"content-security-policy",
                        b"default-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
                    ),
                ]
                headers.extend((name, value) for name, value in defaults if name not in existing)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, secure_send)


def _auth_dependency(api_token: str | None) -> Callable[..., Any]:
    async def require_bearer_token(
        authorization: Optional[str] = Header(default=None),  # noqa: UP045
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


def _error_payload(code: str, message: str, request: Request) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": getattr(request.state, "request_id", None),
        }
    }


def _validate_inline_public_key(value: str) -> None:
    """Reject URL/key-set input and remote JWK references before verification."""
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("Public key contains invalid Unicode.") from exc
    if not encoded or len(encoded) > MAX_PUBLIC_KEY_BYTES:
        raise ValueError("Public key content is empty or exceeds the 64 KiB limit.")

    stripped = value.strip()
    if not stripped.startswith("{"):
        if "://" in stripped or not (
            stripped.startswith(("-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----"))
        ):
            raise ValueError("Only inline PEM public keys or a single public JWK are accepted.")
        return

    jwk = strict_json_loads(stripped, max_bytes=MAX_PUBLIC_KEY_BYTES)
    if not isinstance(jwk, dict):
        raise TypeError("A public JWK must be a JSON object.")
    unknown_members = set(jwk).difference(_ALLOWED_JWK_MEMBERS)
    if unknown_members:
        raise ValueError("JWK contains unsupported members; remote key references are forbidden.")
    if "kty" not in jwk:
        raise ValueError("A public JWK must include kty.")


def _validate_algorithm_allowlist(algorithms: Sequence[str]) -> None:
    """Reject duplicate or unsupported verification algorithms."""
    if len(set(algorithms)) != len(algorithms):
        raise ValueError("Algorithm allowlist contains duplicates.")
    unsupported = set(algorithms).difference(DEFAULT_ASYMMETRIC_ALGORITHMS)
    if unsupported:
        raise ValueError("Algorithm allowlist contains unsupported values.")


class _AsyncSemaphore:
    """Create an asyncio semaphore lazily on the active application event loop."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._loop: Optional[asyncio.AbstractEventLoop] = None  # noqa: UP045 - Python 3.9 compatibility
        self._semaphore: Optional[asyncio.Semaphore] = None  # noqa: UP045 - Python 3.9 compatibility

    async def __aenter__(self) -> _AsyncSemaphore:
        loop = asyncio.get_running_loop()
        semaphore = self._semaphore
        if semaphore is None or self._loop is not loop:
            semaphore = asyncio.Semaphore(self.limit)
            self._semaphore = semaphore
            self._loop = loop
        await semaphore.acquire()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        semaphore = self._semaphore
        if semaphore is not None:
            semaphore.release()


async def _run_bounded(
    request: Request,
    function: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    async with request.app.state.assessment_semaphore:
        return await run_in_threadpool(function, *args, **kwargs)


def _request_validation_status(exc: RequestValidationError) -> tuple[int, str]:
    for error in exc.errors():
        location = error.get("loc", ())
        error_type = str(error.get("type", ""))
        field = location[-1] if location else None
        if field in {"token", "public_key"} and (
            error_type in {"value_error.any_str.max_length", "string_too_long"}
        ):
            return 413, "payload_too_large"
        if error_type in {"value_error.jsondecode", "json_invalid"}:
            return 400, "invalid_json"
    return 422, "invalid_request"


def create_app(
    *,
    api_token: str | None = None,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    requests_per_minute: int = _DEFAULT_RATE_PER_MINUTE,
    request_timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
    max_concurrent_assessments: int = _DEFAULT_MAX_CONCURRENT_ASSESSMENTS,
    allowed_hosts: Sequence[str] | None = None,
) -> FastAPI:
    """Create the optional HTTP API with bounded inputs, time and concurrency.

    The CLI refuses remote binds unless remote exposure, a strong bearer token
    and exact Host values are all explicitly supplied.
    """
    if api_token is not None:
        if not isinstance(api_token, str) or not api_token.strip():
            raise ValueError("api_token must be a non-empty string when supplied")
        if len(api_token) < _REMOTE_TOKEN_MIN_LENGTH:
            raise ValueError("api_token must contain at least 32 characters")

    if (
        isinstance(max_request_bytes, bool)
        or not isinstance(max_request_bytes, int)
        or not 1 <= max_request_bytes <= _MAX_REQUEST_BYTES
    ):
        raise ValueError("max_request_bytes must be between 1 byte and 8 MiB")
    if (
        isinstance(requests_per_minute, bool)
        or not isinstance(requests_per_minute, int)
        or not 1 <= requests_per_minute <= 100_000
    ):
        raise ValueError("requests_per_minute must be between 1 and 100000")
    if (
        isinstance(request_timeout_seconds, bool)
        or not isinstance(request_timeout_seconds, (int, float))
        or not 0.05 <= request_timeout_seconds <= _MAX_REQUEST_TIMEOUT_SECONDS
    ):
        raise ValueError("request_timeout_seconds must be between 0.05 and 120 seconds")
    if (
        isinstance(max_concurrent_assessments, bool)
        or not isinstance(max_concurrent_assessments, int)
        or not 1 <= max_concurrent_assessments <= _MAX_CONCURRENT_ASSESSMENTS
    ):
        raise ValueError("max_concurrent_assessments must be between 1 and 32")

    if allowed_hosts is None:
        host_allowlist = ["127.0.0.1", "localhost", "[::1]"]
    else:
        if isinstance(allowed_hosts, (str, bytes)) or not allowed_hosts:
            raise ValueError("allowed_hosts must be a non-empty sequence of host names")
        if any(not isinstance(host, str) or not host.strip() for host in allowed_hosts):
            raise ValueError("allowed_hosts entries must be non-empty strings")
        host_allowlist = [host.strip().lower() for host in allowed_hosts]
        if any("*" in host for host in host_allowlist):
            raise ValueError("Wildcard host entries are not supported")

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.ready = True
        try:
            yield
        finally:
            application.state.ready = False

    app = FastAPI(
        title="JWT Analyzer API",
        description=(
            "Versioned JWT inspection and explicit public-key verification. "
            "This service never fetches remote JWKS or arbitrary URLs."
        ),
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )
    app.state.ready = True
    app.state.assessment_semaphore = _AsyncSemaphore(max_concurrent_assessments)
    authorize = _auth_dependency(api_token)

    app.add_middleware(MaxRequestBodyMiddleware, max_body_bytes=max_request_bytes)
    app.add_middleware(RequestRateLimitMiddleware, requests_per_minute=requests_per_minute)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=host_allowlist,
        www_redirect=False,
    )
    app.add_middleware(RequestTimeoutMiddleware, timeout_seconds=float(request_timeout_seconds))
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    # Added last so the safe error boundary wraps every other middleware. In
    # particular, the body-limit middleware must see and translate its own
    # streamed-body sentinel before the generic exception boundary.
    app.add_middleware(SafeErrorMiddleware)

    @app.exception_handler(HTTPException)
    async def handle_http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code = "unauthorized" if exc.status_code == 401 else "http_error"
        message = (
            exc.detail if isinstance(exc.detail, str) else "The request could not be completed."
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(code, message, request),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        status_code, code = _request_validation_status(exc)
        messages = {
            400: "Request body must be valid JSON.",
            413: "A request field exceeds the configured size limit.",
            422: "Request body does not match the documented API schema.",
        }
        return JSONResponse(
            status_code=status_code,
            content=_error_payload(code, messages[status_code], request),
        )

    @app.get(
        "/api/v1/health",
        response_model=HealthResponse,
        tags=["health"],
        summary="Compatibility health check",
    )
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get(
        "/api/v1/health/live",
        response_model=HealthResponse,
        tags=["health"],
        summary="Liveness probe",
    )
    async def liveness() -> dict[str, str]:
        return {"status": "alive", "version": __version__}

    @app.get(
        "/api/v1/health/ready",
        response_model=HealthResponse,
        responses={503: {"model": ErrorResponse, "description": "Service is shutting down."}},
        tags=["health"],
        summary="Readiness probe",
    )
    async def readiness(request: Request) -> dict[str, str]:
        if not request.app.state.ready:
            raise HTTPException(status_code=503, detail="Service is not ready.")
        return {"status": "ready", "version": __version__}

    @app.post(
        "/api/v1/inspect",
        response_model=dict[str, Any],
        responses={
            400: {"model": ErrorResponse},
            401: {"model": ErrorResponse},
            408: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
            429: {"model": ErrorResponse},
        },
        tags=["assessment"],
        summary="Inspect a compact JWT without verifying its signature",
    )
    async def inspect_endpoint(
        payload: InspectRequest,
        request: Request,
        _auth: Any = Depends(authorize),
    ) -> JSONResponse:
        try:
            assessment = await _run_bounded(request, inspect_token, payload.token)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="JWT structure or claims are invalid.",
            ) from exc
        return JSONResponse(assessment.to_dict())

    @app.post(
        "/api/v1/verify",
        response_model=dict[str, Any],
        responses={
            400: {"model": ErrorResponse},
            401: {"model": ErrorResponse},
            408: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
            429: {"model": ErrorResponse},
        },
        tags=["assessment"],
        summary="Verify a JWT using an explicitly supplied public key",
    )
    async def verify_endpoint(
        payload: VerifyRequest,
        request: Request,
        _auth: Any = Depends(authorize),
    ) -> JSONResponse:
        try:
            _validate_inline_public_key(payload.public_key)
            _validate_algorithm_allowlist(payload.algorithms)
            assessment = await _run_bounded(
                request,
                verify_with_public_key,
                payload.token,
                payload.public_key,
                algorithms=payload.algorithms,
                issuer=payload.issuer,
                audience=payload.audience,
                leeway=payload.leeway,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="Invalid token, inline public key, or verification options.",
            ) from exc
        return JSONResponse(assessment.to_dict())

    @app.post(
        "/api/v1/report",
        response_model=dict[str, Any],
        tags=["reporting"],
        summary="Render a schema-validated assessment report with redaction by default",
    )
    async def report_endpoint(
        payload: ReportRequest,
        request: Request,
        _auth: Any = Depends(authorize),
    ) -> JSONResponse:
        try:
            assessment = Assessment.from_dict(payload.assessment)
            report_format = ReportFormat(payload.format)
            content = await _run_bounded(
                request,
                render_report,
                assessment,
                report_format,
                include_sensitive=payload.include_sensitive,
            )
        except (KeyError, TypeError, ValueError):
            raise HTTPException(
                status_code=422,
                detail="Assessment or report options are invalid.",
            ) from None
        return JSONResponse(
            {
                "format": report_format.value,
                "content": content,
                "redaction_applied": not payload.include_sensitive,
            }
        )

    @app.get(
        "/dashboard",
        response_class=HTMLResponse,
        tags=["dashboard"],
        summary="Same-origin local assessment dashboard",
    )
    async def dashboard() -> HTMLResponse:
        nonce = secrets.token_urlsafe(18)
        html = _DASHBOARD_HTML.replace("__CSP_NONCE__", nonce)
        csp = (
            "default-src 'self'; "
            f"script-src 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self'; "
            "frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"
        )
        return HTMLResponse(
            html,
            headers={"Content-Security-Policy": csp, "Cache-Control": "no-store"},
        )

    return app


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip()
    if normalized.casefold() == "localhost":
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> None:
    """Run the service with loopback-only defaults and explicit remote opt-in."""
    parser = argparse.ArgumentParser(description="Run the optional JWT Analyzer HTTP service.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765).")
    parser.add_argument(
        "--api-token",
        default=os.environ.get("JWT_ANALYZER_API_TOKEN"),
        help="Bearer token; may also be supplied via JWT_ANALYZER_API_TOKEN.",
    )
    parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help="Exact allowed HTTP Host value; repeat for multiple names. Wildcards are rejected.",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Explicitly permit a non-loopback bind; requires a strong bearer token and Host allowlist.",
    )
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=DEFAULT_MAX_REQUEST_BYTES,
        help="Maximum HTTP request body size (default: approximately 2 MiB).",
    )
    parser.add_argument(
        "--requests-per-minute",
        type=int,
        default=_DEFAULT_RATE_PER_MINUTE,
        help="Per-client request limit for assessment routes.",
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=_DEFAULT_REQUEST_TIMEOUT_SECONDS,
        help="Maximum time allowed for one HTTP request.",
    )
    parser.add_argument(
        "--max-concurrent-assessments",
        type=int,
        default=_DEFAULT_MAX_CONCURRENT_ASSESSMENTS,
        help="Maximum concurrent CPU-bound assessment operations.",
    )
    args = parser.parse_args(argv)

    if not 1 <= args.port <= _MAX_PORT:
        parser.error("--port must be between 1 and 65535")
    loopback = _is_loopback_host(args.host)
    if not loopback and not args.allow_remote:
        parser.error("Non-loopback binds require --allow-remote.")
    if not loopback and not args.api_token:
        parser.error("Non-loopback binds require --api-token or JWT_ANALYZER_API_TOKEN.")
    if not loopback and len(args.api_token) < _REMOTE_TOKEN_MIN_LENGTH:
        parser.error("Non-loopback binds require a bearer token at least 32 characters long.")
    if not loopback and not args.allowed_host:
        parser.error("Non-loopback binds require at least one explicit --allowed-host.")
    if any("*" in host for host in args.allowed_host):
        parser.error("Wildcard Host allowlists are not permitted.")
    if args.api_token is not None and len(args.api_token) < _REMOTE_TOKEN_MIN_LENGTH:
        parser.error("--api-token must contain at least 32 characters.")
    if not 1 <= args.max_request_bytes <= _MAX_REQUEST_BYTES:
        parser.error("--max-request-bytes must be between 1 byte and 8 MiB.")
    if not 1 <= args.requests_per_minute <= 100_000:
        parser.error("--requests-per-minute must be between 1 and 100000.")
    if not 0.05 <= args.request_timeout <= _MAX_REQUEST_TIMEOUT_SECONDS:
        parser.error("--request-timeout must be between 0.05 and 120 seconds.")
    if not 1 <= args.max_concurrent_assessments <= _MAX_CONCURRENT_ASSESSMENTS:
        parser.error("--max-concurrent-assessments must be between 1 and 32.")

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on optional install extra
        parser.error(
            "Install the optional service dependencies with pip install jwt-analyzer[service]."
        )
        raise SystemExit(2) from exc

    uvicorn.run(
        create_app(
            api_token=args.api_token,
            max_request_bytes=args.max_request_bytes,
            requests_per_minute=args.requests_per_minute,
            request_timeout_seconds=args.request_timeout,
            max_concurrent_assessments=args.max_concurrent_assessments,
            allowed_hosts=args.allowed_host or None,
        ),
        host=args.host,
        port=args.port,
        access_log=False,
        server_header=False,
        proxy_headers=False,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=15,
        limit_concurrency=args.max_concurrent_assessments + 16,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
