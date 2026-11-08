"""Real Chromium E2E coverage for the local JWT Analyzer dashboard."""

import json
import socket
import threading
import time
from dataclasses import replace

import pytest

pytest.importorskip("playwright.sync_api")
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from playwright.sync_api import sync_playwright

from jwt_analyzer.api import inspect_token
from jwt_analyzer.models import Confidence, Finding, Severity
from jwt_analyzer.service import create_app


@pytest.fixture(scope="module")
def dashboard_url():
    import uvicorn

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    server = uvicorn.Server(
        uvicorn.Config(
            create_app(),
            host="127.0.0.1",
            port=port,
            log_level="critical",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        if not thread.is_alive():
            raise RuntimeError("dashboard test server stopped before startup")
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("dashboard test server did not start")

    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def _signed_token():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    token = jwt.encode(
        {
            "sub": "e2e-user",
            "email": "private@example.test",
            "exp": 4102444800,
            "iss": "https://issuer.example",
            "aud": "jwt-api",
        },
        private_key,
        algorithm="RS256",
    )
    return token, public_key


def test_dashboard_browser_workflows_accessibility_and_safe_rendering(dashboard_url):
    token = jwt.encode(
        {
            "sub": '<img src=x onerror="window.__jwtXss=1">',
            "email": "private@example.test",
            "exp": 4102444800,
        },
        "dashboard-e2e-secret-key-at-least-32-bytes-long",
        algorithm="HS256",
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.goto(dashboard_url + "/dashboard", wait_until="networkidle")

        # Keyboard focus and labels are available before any form interaction.
        page.locator("#api-token").focus()
        page.keyboard.press("Tab")
        assert page.evaluate("document.activeElement.id") == "jwt-file"
        assert page.locator('label[for="jwt-file"]').count() == 1
        assert page.locator('[aria-live="polite"]').count() >= 2

        # File selection is local; the token is sent only after explicit submit.
        requests = []
        page.on("request", lambda request: requests.append(request.url))
        page.locator("#jwt-file").set_input_files(
            {
                "name": "assessment.jwt",
                "mimeType": "text/plain",
                "buffer": token.encode("utf-8"),
            }
        )
        assert page.locator("#jwt").input_value() == token
        assert not any(url.endswith("/api/v1/inspect") for url in requests)
        page.get_by_role("button", name="Inspect token").click()
        page.wait_for_function(
            "document.querySelector('#status').textContent.includes('Inspection completed')"
        )
        displayed = page.locator("#result").inner_text()
        assert "private@example.test" not in displayed
        assert page.locator("#result img").count() == 0
        assert page.evaluate("window.__jwtXss || false") is False

        # JSON export is downloaded through the report API and remains redacted.
        with page.expect_download() as download_info:
            page.get_by_role("button", name="Export report").click()
        download = download_info.value
        downloaded_path = download.path()
        assert downloaded_path is not None
        exported = open(downloaded_path, encoding="utf-8").read()
        assert "private@example.test" not in exported

        # Explicit verification uses the supplied inline public key and allowlist.
        signed_token, public_key = _signed_token()
        page.locator("#verify-jwt").fill(signed_token)
        page.locator("#public-key").fill(public_key)
        page.locator("#algorithms").fill("RS256")
        page.get_by_role("button", name="Verify signature").click()
        page.wait_for_function(
            "document.querySelector('#status').textContent.includes('Signature verification completed')"
        )
        assert '"verification_status": "verified"' in page.locator("#result").inner_text()

        # Comparison accepts assessment JSON and reports stable finding deltas.
        first = inspect_token(token)
        extra = Finding(
            id="e2e.added_finding",
            title="E2E comparison marker",
            description="Added in the later assessment.",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
        )
        second = replace(first, findings=first.findings + (extra,))
        page.locator("#compare-a").fill(json.dumps(first.to_dict()))
        page.locator("#compare-b").fill(json.dumps(second.to_dict()))
        page.get_by_role("button", name="Compare findings").click()
        page.wait_for_function(
            "document.querySelector('#comparison').textContent.includes('e2e.added_finding')"
        )
        assert '"added": 1' in page.locator("#comparison").inner_text()

        # Narrow viewports collapse the dashboard grid to one column.
        page.set_viewport_size({"width": 390, "height": 844})
        columns = page.locator(".grid").first.evaluate(
            "(element) => getComputedStyle(element).gridTemplateColumns"
        )
        assert len(columns.split()) == 1

        # Invalid input produces a safe failure state rather than raw error data.
        page.locator("#jwt").fill("not-a-jwt")
        page.get_by_role("button", name="Inspect token").click()
        page.wait_for_function(
            "document.querySelector('#status').textContent.includes('Inspection failed')"
        )
        assert "not-a-jwt" not in page.locator("#result").inner_text()
        browser.close()
