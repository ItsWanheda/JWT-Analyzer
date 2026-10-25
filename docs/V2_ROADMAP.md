# JWT Analyzer 2.0.0 Roadmap

**Target branch:** `v2.0.0`  
**Development version:** `2.0.0.dev0`  
**Primary interfaces:** CLI and Python API  
**Expanded scope:** optional HTTP service, graphical dashboard, versioned plugin API  
**Release status:** unreleased; no release/tag/publication is authorized by this roadmap.

## Baseline and non-negotiable constraints

- PR #4 introduced the v2 foundation on `main`; this roadmap still treats v2 as unreleased development work. A merged PR and source-tree inspection are not substitutes for reproducible tests, clean install evidence, or adversarial security testing.
- The v2 CLI and API represent `alg=none` as an indicator rather than a confirmed bypass. M0 adds expanded regression coverage for that behavior and sensitive-output handling.
- The wheel configuration explicitly includes `jwt_analyzer/`, `core/`, `utils/`, `plugins/`, `main.py`, `config.py`, and the starter wordlist. M0 verifies the wheel and source distribution, then installs the wheel in an isolated environment and executes a CLI smoke test.
- The existing CI matrix covers Python 3.9–3.14, the optional service, and package builds. M0 adds JWKS adversarial tests, static security scanning, clean-wheel smoke tests, and a Docker starter-wordlist check.
- JWKS retrieval must connect to the same validated address tuples it inspected. Allowing the HTTP client to resolve the hostname again at connect time is not sufficient to prevent DNS time-of-check/time-of-use attacks.
- All new work stays on `v2.0.0` and follow-up branches. Do not force-push shared branches, modify `main`, merge into `main`, publish to PyPI/Docker, or create a release/tag as part of routine implementation.

## Delivery milestones

### M0 — Validate and stabilize the security baseline

**Goal:** make the merged security claims reproducible, close packaging and JWKS gaps, and introduce required CI evidence.

Issues:
- [x] **M0-01 — Run the full regression suite**: execute existing and PR #3 tests on a clean checkout; repair failures rather than suppressing them.
- [x] **M0-02 — Correct the `alg=none` finding semantics**: emit a medium-severity indicator with explicit confidence scope and a limitation stating that a token header alone cannot establish target-side bypass.
- [x] **M0-03 — Harden JWKS destination validation**: pin validated DNS answers to the TLS connection; reject mixed public/private answers, unsafe numeric host forms, redirects, compressed/oversized bodies and malformed/private JWK material; bound DNS answer fan-out and cache growth; enforce a monotonic connection/response deadline; test address pinning, IPv4/IPv6, cache isolation and failure behavior.
- [x] **M0-04 — Verify wheel contents and clean install**: package all modules required by the CLI; build sdist and wheel; inspect `dist`; install into a clean environment; run `jwt-analyzer --version` and a smoke command.
- [x] **M0-05 — Add required branch CI**: test on every supported Python version; run regression tests, build/install smoke tests, lint and type checks. CI must expose failures instead of relying on undocumented local runs.
- [x] **M0-06 — Audit output and secret-handling paths**: assert no original token, recovered signing secret, credential or PII leak into logs, JSON, HTML, exceptions or CI logs unless explicitly requested in a controlled local workflow.
- [x] **M0-07 — Align version and security-support docs**: version metadata, CLI version, README, changelog, `SECURITY.md`, Docker, tox and package metadata must agree.
- [x] **M0-08 — Make bundled wordlist policy explicit**: ship the reviewed starter list in the image; any larger built-in corpus must be versioned and checksummed, with operator-supplied lists remaining an explicit opt-in.

**Acceptance:** reproducible green test/build evidence; no high/critical unresolved security defects; JWKS adversarial tests pass; clean installation proves CLI and public API imports work; default output redaction is regression-tested; the starter wordlist is present and documented in package and image. Do not mark M0 complete until M0 branch CI is green.

### M1 — Shared assessment engine and result contract

**Goal:** separate token parsing, cryptographic verification, policy evaluation and presentation from the legacy CLI.

Issues:
- [x] **M1-01 — Freeze the normalized result schema**: publish schema v1.1 for `Assessment` and `Finding`; include severity, confidence, verification/policy status, warnings/errors, timestamp, stage and schema version. Result models do not include a raw-token field.
- [x] **M1-02 — Define finding semantics**: findings expose stable IDs, stage, observation, confidence, impact, evidence, limitations and remediation. Token-only heuristics remain indicators, not confirmed remote vulnerabilities.
- [x] **M1-03 — Separate parse / verify / policy stages**: parsing leaves claims untrusted; signature verification uses explicit public-key and asymmetric algorithm constraints without checking issuer/audience/time claims; policy evaluation is a separate operation.
- [x] **M1-04 — Add policy profiles**: baseline, strict and user-defined `AssessmentPolicy` profiles cover issuer, audience, time claims, required claims, accepted algorithms and clock leeway.
- [x] **M1-05 — Make assessments deterministic**: stable severity-then-ID finding order, unique finding IDs, UTC ISO-8601 timestamps, strict JSON round-tripping, public schema and deterministic contract fixtures.

**Acceptance:** public models have contract tests; malformed input fails predictably; inspection never returns a verified status; signature and policy statuses are separate; JSON round-trips preserve schema and finding IDs; equivalent input and policy produce stable finding ordering.

### M2 — Cryptographic verification and security intelligence

Issues:
- [ ] **M2-01 — Verification matrix**: RSA, ECDSA, Ed25519/OKP and supported HMAC tests, key/algorithm mismatch tests, malformed keys, expired/not-yet-valid claims, issuer/audience validation, and explicit algorithm allowlists.
- [ ] **M2-02 — JWKS adversarial tests**: SSRF, redirects, DNS changes, TLS failures, content-type and body limits, duplicate `kid`, ambiguous keys, key-use/key-ops/algorithm mismatches, cache expiry and outage behavior.
- [ ] **M2-03 — Bound all expensive work**: test brute-force worker limits, queue bounds, deadlines, cancellation, cleanup, memory limits and behavior when a crypto call cannot be interrupted.
- [ ] **M2-04 — Calibrate severities/confidence**: document every rule; tests must distinguish confirmed local facts, likely indicators and unknown server-side behavior.
- [ ] **M2-05 — Property/fuzz testing**: parser and JSON/JWK boundaries, oversized inputs, unusual Unicode, numeric edge cases and non-object JSON values.

**Acceptance:** all key-type and negative tests pass; no algorithm confusion from attacker-controlled header data; all network and CPU-intensive operations have bounded limits; findings include limitations and reproducible evidence.

### M3 — Stable public Python API and CLI v2

Issues:
- [ ] **M3-01 — Public API stability**: document `jwt_analyzer` imports; annotate public functions; explicit exceptions; API compatibility tests; no accidental exports from internal modules.
- [ ] **M3-02 — Versioned CLI contract**: stable commands, argument validation, structured error format and exit-code contract; support JSON output on stdout for scripting.
- [ ] **M3-03 — Batch assessment**: stream files and batches without unbounded memory use; per-item outcomes; safe partial failures and machine-readable summaries.
- [ ] **M3-04 — Configuration and policy loading**: validate config schemas, merge precedence, environment overrides, path handling and safe defaults.
- [ ] **M3-05 — Migration aliases and removals**: add only time-bounded compatibility aliases that do not weaken security; document removed flags and changed output fields.

**Acceptance:** CLI golden tests and API contract tests pass on supported Python versions; stdout/stderr behavior and exit codes are documented; large batches are bounded; no ambiguous decode-versus-verify semantics.

### M4 — Reporting and CI integrations

Issues:
- [ ] **M4-01 — Shared reporter interface**: JSON, HTML and SARIF share the same normalized assessment and severity semantics.
- [ ] **M4-02 — Validate report schemas**: JSON schema, SARIF 2.1.0 validation, deterministic fixtures, escaping, Unicode and redaction regression tests.
- [ ] **M4-03 — CI thresholds**: policy-defined fail thresholds with documented exit codes; do not fail a pipeline on informational findings unless configured.
- [ ] **M4-04 — Secret-safe exports**: redaction defaults, explicit opt-in for sensitive fields, report metadata, and no secret values in logs.

**Acceptance:** output formats agree on counts/severity; report renderers are resistant to HTML injection; SARIF validates against its schema; threshold behavior is covered by integration tests.

### M5 — Optional HTTP service

**Initial implementation on branch `v2.0.0`:** an opt-in FastAPI/Uvicorn extra now exposes `/api/v1/health`, `/api/v1/inspect`, and `/api/v1/verify`, plus a same-origin `/dashboard`. It defaults to loopback, can require bearer authentication, checks Host values, caps body size, rate-limits assessment routes, adds security headers/CSP, and does not persist request bodies. See [HTTP service documentation](HTTP_SERVICE.md). This is a first slice, not completion of the milestone.

Issues:
- [ ] **M5-01 — Versioned service contract**: optional install extra, `/api/v1` health and assessment routes, request/response schemas and OpenAPI docs.
- [ ] **M5-02 — Secure service defaults**: bind to loopback by default; require explicit opt-in to expose remotely; auth, rate limits, body size, timeout and concurrency limits; no persistent token storage by default.
- [ ] **M5-03 — SSRF boundary**: untrusted requests cannot ask the service to fetch arbitrary JWKS/URLs without policy and egress restrictions; no redirects and explicit destination allowlists.
- [ ] **M5-04 — Lifecycle and telemetry**: clean shutdown, readiness/liveness, structured redacted logs, no tokens in traces, defined error envelopes.
- [ ] **M5-05 — Service abuse tests**: auth bypass, request flooding, oversized bodies, slow clients, SSRF, malformed schemas, CORS and exception leakage.

**Acceptance:** service is optional and absent from the default CLI dependency path; safe default bind; authenticated/authorized remote use; rate/size/time caps and abuse tests pass; raw tokens are not persisted or logged.

### M6 — Graphical dashboard and extension ecosystem

**Initial implementation on branch `v2.0.0`:** a responsive same-origin dashboard supports token inspection with per-response CSP nonce and text-only result rendering; it does not persist input or output. Verification controls, assessment comparison, export/redaction workflows, plugin loading and full E2E/accessibility coverage remain open.

Issues:
- [ ] **M6-01 — Dashboard assessment workflow**: upload/paste, inspect, separately verify, view findings, explain evidence/limitations, and compare assessments.
- [ ] **M6-02 — Safe UI state and exports**: redact by default; make sensitive-data visibility deliberate; no token persistence by default; CSP and HTML sanitization.
- [ ] **M6-03 — Versioned plugin contract**: entry-point discovery, declared capabilities, schema/versioning, deterministic execution and error isolation.
- [ ] **M6-04 — Plugin trust boundary**: plugins are executable code; never auto-load arbitrary files from a working directory; require explicit enablement and document trust/sandbox limitations.
- [ ] **M6-05 — E2E/accessibility testing**: keyboard navigation, screen reader labels, responsive layout, service/API failure states, auth and cross-site scripting regression suite.

**Acceptance:** dashboard only calls the shared engine/service; all state and exports are explicit; plugin loading is opt-in and documented; E2E, accessibility and security tests pass. If dashboard scope slips, ship the core/API/service milestones rather than compromising security gates.

### M7 — Release candidate and 2.0.0 gate

Issues:
- [ ] **M7-01 — Migration guide**: command/API/config/report changes from 1.2.x; before/after examples and removal table.
- [ ] **M7-02 — Clean install matrix**: wheel, sdist, Docker build, editable install, Windows/Linux/macOS smoke tests and all supported Python versions.
- [ ] **M7-03 — Supply-chain artifacts**: dependency audit, SBOM, provenance/attestation and reproducible build record where supported.
- [ ] **M7-04 — Independent security review**: review source, tests, JWKS/SSRF boundaries, output redaction, service/UI and plugins; track findings to closure.
- [ ] **M7-05 — Release notes and operator checklist**: breaking changes, supported versions, known limitations, install/rollback instructions and upgrade steps.

**Acceptance:** no unresolved critical/high release blocker; CI green on the full supported matrix; schema and CLI contracts documented; migration guide reviewed; reports pass security tests; packaged installs work; explicit maintainer approval required before tagging or publishing.

## Dependency order

`M0 → M1 → M2 → M3 → M4 → M7`  
`M3 → M5 → M6 → M7`

M1's result schema and M2's verifier/policy boundary block service or dashboard decisions. M4 can develop in parallel after M1. M5 depends on the public API and SSRF policy. M6 depends on stable service/API behavior. M7 is a gate, not a feature sprint.

## Compatibility policy for the major version

- The `jwt_analyzer` package is the supported v2 import surface; internals are not a compatibility promise.
- v2 may intentionally change CLI flags, output JSON fields, config keys, plugin API and report layout. Each breaking change requires migration documentation and tests.
- Cryptographic verification must be explicit; decoding claims never implies trust.
- Security safeguards (algorithm allowlists, TLS verification, bounded input, safe network defaults and redaction) are not removed merely to preserve v1 behavior.
- The target `2.0.0` version stays a development version until all M7 gates pass. Do not tag or publish a development branch.
