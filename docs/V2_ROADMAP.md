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
- [x] **M2-01 — Verification matrix**: RSA, ECDSA, Ed25519/OKP and supported HMAC tests, key/algorithm mismatch tests, malformed keys, expired/not-yet-valid claims, issuer/audience validation, and explicit algorithm allowlists.
- [x] **M2-02 — JWKS adversarial tests**: SSRF, redirects, DNS changes, TLS failures, content-type and body limits, duplicate `kid`, ambiguous keys, key-use/key-ops/algorithm mismatches, cache expiry and outage behavior.
- [x] **M2-03 — Bound all expensive work**: test brute-force worker limits, queue bounds, deadlines, cancellation, cleanup, memory limits and behavior when a crypto call cannot be interrupted.
- [x] **M2-04 — Calibrate severities/confidence**: document every rule; tests must distinguish confirmed local facts, likely indicators and unknown server-side behavior.
- [x] **M2-05 — Property/fuzz testing**: parser and JSON/JWK boundaries, oversized inputs, unusual Unicode, numeric edge cases and non-object JSON values.

**Acceptance:** all key-type and negative tests pass; no algorithm confusion from attacker-controlled header data; all network and CPU-intensive operations have bounded limits; findings include limitations and reproducible evidence.

**M2 completion:** Implemented and verified on `v2.0.0` in commit `9b24aa511882bba60ffe56bf7e748c28253f2715`. The five M2 test modules contain 46 focused regression/property tests. The full CI workflow passed across Python 3.9–3.14, public API and M2 quality gates, optional HTTP-service security tests, Docker validation, and clean distribution build/install.

**Operational boundary:** The OS DNS resolver cannot be force-cancelled portably. JWKS callers now share one absolute deadline across DNS, connect, TLS, and response reading. A stuck OS resolver can occupy the single daemon DNS worker; one pending request is permitted and additional lookups fail closed rather than expanding the worker pool. See `docs/JWKS_SECURITY.md`.

### M3 — Stable public Python API and CLI v2

Issues:
- [x] **M3-01 — Public API stability**: document the supported `jwt_analyzer` import surface; expose an explicit `__all__`; provide stable public exception types; normalize malformed-token inspection failures; test exports and API behavior.
- [x] **M3-02 — Versioned CLI contract**: add the `jwt-analyzer-v2` entry point; define inspect and batch commands, structured JSON stdout/stderr, stable error codes, and exit-code behavior; keep legacy CLI behavior separate during migration.
- [x] **M3-03 — Batch assessment**: stream token inputs and per-item outcomes without materializing the batch; continue after malformed items; enforce a hard configurable item limit; provide machine-readable summaries.
- [x] **M3-04 — Configuration and policy loading**: validate JSON/YAML configuration with safe YAML loading and a 1 MiB file cap; reject unknown keys; support defaults < config file < environment precedence; expose validated policy profiles and batch limits.
- [x] **M3-05 — Migration aliases and removals**: document the public compatibility boundary, new CLI contract, configuration, exit codes, legacy behavior, and security-sensitive migration constraints. Existing CLI commands are retained rather than redirected to incompatible output or insecure aliases.

**Acceptance:** CLI golden tests and API contract tests pass on supported Python versions; stdout/stderr behavior and exit codes are documented; large batches are bounded; no ambiguous decode-versus-verify semantics.

**M3 completion:** Implemented on `feat/m3-stable-api-cli` and validated in [v2 CI run #42365419623](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42365419623). All six Python versions (3.9–3.14) passed with 186 tests passed and one optional-service test skipped in the core matrix; the separate optional HTTP service job passed. Public API lint/format/type checks, Bandit, wheel/sdist build and clean-install checks, the installed `jwt-analyzer-v2` version smoke test, and Docker wordlist validation passed.

**Operational boundary:** `jwt-analyzer-v2 inspect` and batch inspection do not verify signatures. `--evaluate-policy` evaluates decoded claims as advisory until cryptographic verification succeeds. The existing `jwt-analyzer` legacy CLI remains available during the migration period; its output is not the v2 JSON contract.

### M4 — Reporting and CI integrations

Issues:
- [x] **M4-01 — Shared reporter interface**: JSON, HTML and SARIF share the same normalized assessment and severity semantics; public renderers use the versioned assessment v1.1 model.
- [x] **M4-02 — Validate report schemas**: validate the JSON report envelope and nested assessment with vendored schemas; validate SARIF 2.1.0 offline; add deterministic fixtures, escaping, Unicode and redaction regression tests.
- [x] **M4-03 — CI thresholds**: configurable severity threshold (none, info, low, medium, high, critical) and documented exit codes; default to high, so informational findings do not fail CI unless explicitly configured.
- [x] **M4-04 — Secret-safe exports**: redact sensitive values by default across JSON, HTML and SARIF; require explicit --include-sensitive opt-in; include safe report metadata and never log token or credential values.

**Acceptance:** output formats agree on counts/severity; report renderers are resistant to HTML injection; SARIF validates against its schema; threshold behavior is covered by integration tests.

**M4 completion:** Implemented on `feat/m4-reporting-ci-integrations` and validated in [v2 CI run #42368541600](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42368541600). The full Python 3.9–3.14 matrix passed with 195 tests passed and one optional-service test skipped in the core matrix; the separate optional HTTP service security job passed. Ruff lint/format, mypy, Bandit, wheel/sdist validation, clean wheel installation including both reporting schemas, the installed report-command smoke check, and Docker wordlist validation passed.

**Operational boundary:** JSON, HTML and SARIF reports use the normalized Assessment v1.1 contract. Sensitive values remain redacted unless the caller explicitly opts in with `--include-sensitive` or `include_sensitive=True`. The default CI threshold is `high`; informational findings do not fail a build unless a stricter threshold is configured. No code-scanning source locations are fabricated for token assessments.

### M5 — Optional HTTP service

**Implementation on `feat/m5-secure-http-service`, corrected and validated on `feat/m6-dashboard-plugin-ecosystem`:** the optional FastAPI/Uvicorn service has strict typed request contracts and a generated local OpenAPI document; liveness/readiness endpoints; loopback-first CLI startup; constant-time bearer authentication; exact Host allowlists; bounded body size, request duration, rate and assessment concurrency; safe error envelopes; request IDs and body-free structured logs; and an explicit inline-key-only verification contract that rejects remote JWK references. The original M5 service matrix included Python 3.9–3.14. M7 deliberately raises the optional-service minimum to Python 3.10 to use security-patched Starlette releases; core CLI/API support remains Python 3.9–3.14, while the optional service is tested on Python 3.10–3.14. See [HTTP service documentation](HTTP_SERVICE.md).

Issues:
- [x] **M5-01 — Versioned service contract**: optional install extra; typed, strict request bodies; versioned health/assessment routes; local OpenAPI document and response/error schemas.
- [x] **M5-02 — Secure service defaults**: loopback bind by default; explicit remote opt-in; 32-character minimum bearer secret; exact Host allowlist; bounded rate, body size, request lifetime and concurrent assessment work; no persistent token storage.
- [x] **M5-03 — SSRF boundary**: verification accepts inline PEM or one public JWK only; reject URL inputs, JWK Sets and remote-reference members; no endpoint performs outbound fetches.
- [x] **M5-04 — Lifecycle and telemetry**: startup/shutdown readiness, liveness, request IDs, structured body-free logs, sanitized JSON errors, bounded Uvicorn shutdown.
- [x] **M5-05 — Service abuse tests**: auth, malformed/extra fields, request flooding, declared and streamed oversized bodies, slow clients, remote JWK references, host validation, no-CORS behavior and exception leakage.

**Acceptance:** service is optional and absent from the default CLI dependency path; safe default bind; authenticated/authorized remote use; rate/size/time caps and abuse tests pass; raw tokens are not persisted or logged.

**M5 completion:** the service implementation and security tests passed before M7 dependency hardening. M7 now supports the optional service on Python 3.10–3.14 to use security-patched FastAPI/Starlette, while the core CLI/API remain supported on Python 3.9–3.14. The updated full suite passed all six core versions, five service versions, the 18 Linux/Windows/macOS install combinations, quality, E2E, packaging and Docker checks in [v2 CI run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094) (33/33 jobs).


### M6 — Graphical dashboard and extension ecosystem

**M6 implementation integrated into `v2.0.0`; all M6 gates validated:** the dashboard supports local JWT file selection or paste, separate inspection and explicit inline-key verification, local assessment comparison, and JSON/HTML/SARIF exports through the shared redaction/schema engine. A versioned entry-point plugin contract and explicit opt-in manager are implemented. The corrected Chromium browser E2E/accessibility suite and all core/service/security/quality/package/Docker jobs passed in [full CI run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094) on candidate commit `a2640e9` (33/33 jobs). The earlier RUF005 issue is resolved.

Issues:
- [x] **M6-01 — Dashboard assessment workflow**: upload/paste, inspect, separately verify, view findings, explain evidence/limitations, and compare assessments.
- [x] **M6-02 — Safe UI state and exports**: redact by default; make sensitive-data visibility deliberate; no token persistence by default; CSP and HTML sanitization.
- [x] **M6-03 — Versioned plugin contract**: entry-point discovery, declared capabilities, schema/versioning, deterministic execution and error isolation.
- [x] **M6-04 — Plugin trust boundary**: plugins are executable code; never auto-load arbitrary files from a working directory; require explicit enablement and document trust/sandbox limitations.
- [x] **M6-05 — E2E/accessibility testing**: keyboard navigation, screen reader labels, responsive layout, service/API failure states, auth and cross-site scripting regression suite.

**Acceptance:** dashboard only calls the shared engine/service; all state and exports are explicit; plugin loading is opt-in and documented; E2E, accessibility and security tests pass. If dashboard scope slips, ship the core/API/service milestones rather than compromising security gates.

### M7 — Release candidate and 2.0.0 gate

**M7 technical candidate gates validated; approval gates remain open.** The candidate branch is `feat/m7-release-candidate`. The candidate source at `a2640e9` passed the full v2 CI matrix in [run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094) (33/33 jobs), including core tests on CPython 3.9–3.14, optional HTTP-service security tests on 3.10–3.14, the 18 Linux/Windows/macOS install combinations, public API quality checks, Chromium dashboard E2E, clean distribution installs and Docker validation. The supply-chain workflow for candidate commit `a2640e98` passed in [run #42502255064](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255064): dependency audit, CycloneDX SBOM, repeat-build comparison, package digests, SLSA provenance and CycloneDX attestations, plus in-workflow repository/signer/predicate verification. The downloaded artifact's four SHA-256 manifest entries were independently checked; the audit covers 88 dependency components and reported zero advisories. The repeat-build claim is limited to the same source commit, hosted runner and toolchain, not independent or cross-platform reproducibility.

The dependency audit earlier exposed a vulnerable Starlette <1.0 resolution. The service extra now uses the patched FastAPI/Starlette line on Python 3.10+, while the core CLI/API retain Python 3.9 support; service tests use the Starlette 1.x-compatible `httpx2` test client. M6-05 is closed. The migration guide, release notes and operator checklist are prepared but still require operator/maintainer review. No final release clearance is claimed until M7-01, M7-04 and M7-05 are signed off. No version bump, tag, PyPI publication, Docker push or production cutover is included.

Issues:
- [ ] **M7-01 — Migration guide review**: command/API/config/report changes from 1.2.x are documented with before/after examples and non-equivalent command mappings; an operator who owns a v1.2.x integration must review and sign off.
- [x] **M7-02 — Clean-install matrix**: editable, wheel and sdist smoke checks passed across Linux, Windows and macOS × CPython 3.9–3.14; core/service regressions, package build/install and Docker wordlist validation passed in [v2 CI run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094) (33/33 jobs).
- [x] **M7-03 — Supply-chain artifacts**: dependency audit, CycloneDX SBOM, wheel/sdist SHA-256 manifest, build record, same-run repeat-build comparison, SLSA provenance and SBOM attestations all passed in [M7 supply-chain run #42502255064](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255064), including repository/signer/predicate verification.
- [ ] **M7-04 — Independent security review**: reviewer other than the implementation author must inspect source, tests, JWKS/SSRF boundaries, output redaction, service/UI and plugin trust boundary; track findings to closure.
- [ ] **M7-05 — Release notes and operator checklist approval**: draft covers breaking changes, supported versions, known limitations, install/rollback instructions and upgrade steps; maintainer/operator approval remains pending.

**Acceptance:** M7-02 and M7-03 technical gates pass on the candidate evidence above; migration review and independent security review remain mandatory. Do not claim there are no critical/high release blockers until an independent reviewer records the result. Release notes and operator checklist remain drafts. Explicit maintainer authorization is required before changing package metadata, tagging, publishing or production rollout.

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
