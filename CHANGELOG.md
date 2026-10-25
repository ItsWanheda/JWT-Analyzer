# Changelog

All notable changes to this project will be documented in this file.

---

## [Unreleased — v2.0.0 development]

### M0 security-baseline hardening

- Pin JWKS HTTPS connections to validated DNS address tuples while preserving TLS hostname verification; reject mixed public/private DNS answers, non-canonical numeric IP forms, redirects, compressed/oversized bodies, private JWK material, and malformed key metadata.
- Bound JWKS DNS answer fan-out and cache entries; enforce a monotonic deadline over connection, response headers, and chunked body reads; reject non-finite timeouts and port zero.
- Return thread-safe defensive copies from the bounded JWKS cache and restrict verification to supported asymmetric algorithms with sanitized error messages.
- Record `alg=none` as a medium-severity header indicator with explicit confidence scope; do not claim a target-side signature bypass without verifier evidence.
- Add best-effort redaction for JWT-like strings, common credentials, sensitive claim identifiers, PII patterns and scanner match excerpts in report/log paths; stop echoing malformed token contents in file-read errors.
- Expand CI for JWKS adversarial cases, isolated wheel installation, CLI smoke testing, static security scanning and Docker starter-wordlist presence.

> This section documents unreleased branch work. It is not a release announcement.

### M1 shared assessment engine and result contract

- Publish assessment schema v1.1 with strict JSON round-tripping, UTC timestamps, unique stable finding IDs and deterministic severity-then-ID ordering.
- Extend findings with stage, observation, impact, evidence, limitations and remediation.
- Add signature-only public-key verification and separate baseline, strict and custom claim-policy evaluation.
- Keep signature validity independent from issuer, audience and lifetime policy outcomes; unverified policy evaluations are explicitly advisory.
- Add JSON Schema, canonical fixture and regression tests for malformed claims, policy profiles, and signature/policy separation.

> M1 work remains unreleased development functionality.

### Added
- Introduce the public `jwt_analyzer` Python namespace with normalized `Assessment` and `Finding` models.
- Add `inspect_token()` for structural inspection that explicitly leaves verification as `not_attempted`.
- Add `verify_with_public_key()` with an explicit algorithm allowlist, optional issuer/audience validation, leeway control, and distinct verified/invalid/error assessment states.
- Add the optional HTTP service extra with versioned health/inspect/verify routes, loopback-first startup controls, Host validation, bearer authentication, request-size limits, rate limiting, security headers, and a same-origin inspection dashboard.
- Add a v2 milestone roadmap, migration checklist, and branch CI workflow.

### Changed
- Move the development package version to `2.0.0.dev0`; no PyPI/Docker publication or release tag is created.
- Correct CLI finding semantics so `alg=none` is a token-header indicator, not a confirmed server-side signature bypass.
- Correct the missing-`exp` check so numeric timestamp zero is not confused with an absent claim.
- Correct wheel discovery and package metadata for the public API and required legacy modules.
- Update README examples to stop recommending disabled TLS verification.

### Validation
- CI is being added on the v2 branch; passing results are required before the release-candidate milestone.
- No release, tag, or package publication is included in this development work.

---

## [Released]

### [1.2.1] - 2026-07-05

Patch release — fixes discovered during first-run validation on Python 3.14 / Windows.


#### Security hardening

- Distinguish token-header indicators from confirmed server-side JWT vulnerabilities; report suspicious patterns as indicators rather than proof.
- Validate JWT Base64URL segments, JSON object types, expiration claim types, and maximum token length.
- Add explicit RSA, EC, and OKP JWK handling for public-key verification, with optional issuer and audience validation.
- Harden JWKS retrieval with HTTPS enforcement, public-address checks, redirects disabled, response-size limits, and JWK compatibility checks.
- Bound parallel HMAC candidate scheduling and use thread-safe cancellation signals.
- Escape dynamic HTML report fields, redact credential-like values by default, and avoid printing discovered signing secrets.
- Add regression tests for malformed tokens, heuristic finding semantics, JWKS URL restrictions, and report escaping/redaction.

#### Fixed

- **`forge` command crashed with `bytes-like object` error**: `forgery.py` was passing `parts` (a list of 3 strings) to `_base64url_decode` instead of `parts`. Resulted in `argument should be a bytes-like object or ASCII string, not 'list'`.
- **`forge` produced garbage signature segment**: `signed.split('.')` returned a list and was being f-string-interpolated as a Python repr. Replaced with `signed.rsplit('.', 1)[-1]`. Rewrote the HMAC branch to sign directly with `hmac.new()` instead of round-tripping through `jwt.encode()`.
- **`brute-force` workers kept running after a match**: `if stop_flag:` was always truthy (non-empty list). Fixed to `if stop_flag:` so the thread pool actually stops when a secret is cracked.
- **`parser.py` raised `NameError` on tokens with `exp` claim**: `timezone` was referenced but never imported. Added to the `datetime` import.
- **Python 3.14: PII scanner crashed with `re.PatternError: nothing to repeat at position 25`**: IPv4 pattern contained `|?\d\d?` (bare `?` with nothing to repeat). Replaced with `|1?\d\d?`. Also tightened email pattern: `[A-Z|a-z]` → `[A-Za-z]` (the `|` inside a character class was a literal pipe).
- **Windows: token files saved by PowerShell failed to decode** with `'utf-8' codec can't decode byte 0xb1`. Cause: PowerShell `Set-Content` defaults to UTF-8 with BOM on some configs. `read_token_from_file` and `read_text_file` now use `encoding='utf-8-sig'`, which transparently strips a BOM if present.
- **Import mismatch**: `main.py` imported from `core.forgery` but the file was named `forger.py`. Renamed file and refactored to PEP 8 module name.

#### Changed

- `forge_token` now signs HS256/384/512 directly via `hmac.new()` — fewer moving parts and easier to reason about.
- Added explicit `concurrent.futures` shutdown via `with` block on the brute-force thread pool (already present, now verified working post-fix).

#### Notes

- All fixes are backwards compatible. No CLI or config changes.
- Verified end-to-end on Python 3.14.6 / Windows PowerShell 5.1 with the JWT.io demo token.

### Added


---

## [1.2.0] - 2026-06-25

> Note: v1.1.0 was developed but never tagged as a release. All work from
> that iteration is consolidated into 1.2.0 below.

### Added

#### Core security features
- **SARIF** output format for GitHub Code Scanning integration
- **Shell completion** scripts (bash, zsh, fish)
- **New `audit` command**: Runs all security checks in one shot and produces a report
  - Sequential progress UI with Rich
  - Proper exit codes (0/1/2) for CI/CD gating
  - JSON and HTML report output formats (`--output` + `--format`)
- **JWKS endpoint support** (`verify-jwks` command)
  - Fetches keys from `.well-known/jwks.json` URLs
  - In-memory TTL cache (1 hour default) to avoid hammering the endpoint
  - Auto-selects RSA vs EC algorithm based on key type
  - Clear error messages when `kid` isn't found in the JWKS
- **Algorithm confusion detection** (`check_algorithm_confusion`)
  - Flags RS256/ES256 tokens that could be attacked via HS256 confusion
- **`kid` header injection detection** (`check_kid_injection`)
  - SQL injection patterns
  - Path traversal (`../`, `%2e%2e`)
  - Command injection markers (backticks, `$()`, `|`, `;`)
- **PII / sensitive data scanner** (`core/sensitive_scanner.py`)
  - Credit card numbers (with Luhn validation to reduce false positives)
  - US SSNs, phone numbers, emails
  - AWS access keys
  - Nested JWTs (token smuggling indicator)
  - Private key material (PEM blocks)
  - Password / secret fields with values
- **Parallel brute force** (`core/async_security.py`)
  - ThreadPoolExecutor-based, 5-10x faster than sequential
  - Configurable worker count via `JWT_ANALYZER_WORKERS` env var
  - Auto-degrades to sequential for tiny wordlists (<100 secrets)
  - Timeout support with attempt counter on interruption

#### Infrastructure & tooling
- **Structured JSON logging** (`core/logging_config.py`)
  - JSON formatter for SIEM integration (Splunk, ELK, Datadog)
  - Console formatter for human-readable output
  - File logging option (`--log-file`)
- **HTML report generation** (`utils/report.py`)
  - Severity-coded summary cards
  - Findings table with remediation guidance
  - Embedded token info and payload dump
- **Docker support**
  - Multi-stage `Dockerfile` (~150MB final image, down from ~900MB)
  - Non-root user (`jwtuser`, UID 1000)
  - Pre-bundled wordlist from SecLists (~10k JWT secrets) at build time
  - `Dockerfile.dev` for live-reload development
  - `docker-compose.yml` with 5 profiles: `audit`, `ci`, `dev`, `batch`, `jwks`
  - `HEALTHCHECK` directive for orchestration platforms
  - Resource limits (2 CPU / 1GB RAM) to prevent runaway brute force
  - Security hardening: `no-new-privileges`, `cap_drop ALL`, `read_only` fs
- **Makefile** for common workflows (`make install`, `make docker-audit`, etc.)
- **`.env.example`** documenting all environment variables
- **`scripts/batch_audit.sh`** — processes a directory of tokens overnight

#### Configuration
- **`Config` class** with `is_rich_enabled()` and `get_wordlist_path()` helpers
- Environment variable overrides in `config.py`
- Wordlist path configuration via `JWT_ANALYZER_WORDLIST_PATH`
- Brute force timeout via `JWT_ANALYZER_TIMEOUT`
- Configurable log level via `JWT_ANALYZER_LOG_LEVEL`

#### Reporting
- JSON report output for `verify-rsa` command (`--output` flag)

### Changed

#### Breaking changes
- **BREAKING**: `brute_force_secret` no longer tests asymmetric algorithms
  - HS256/384/512 only — RS/ES use keys, not secrets
  - This was a bug that caused false positives with empty strings on RS256
- **BREAKING**: CLI commands renamed from `snake_case` to `kebab-case`
  - `verify_rsa` → `verify-rsa` (old name still works but prints deprecation warning)
- **BREAKING**: Minimum Python version bumped to **3.9**

#### Improvements
- `read_token_from_file` now provides better error messages with token preview
- `forge_token` now preserves custom header fields (`kid`, `jku`, etc.)
- `forge` command requires explicit `--yes` confirmation flag (safety)
- `compare_payloads` now returns a dict with `added`, `removed`, `changed` keys
  (previously had inconsistent format)
- `parse_jwt` gracefully handles missing `exp` claim (returns empty `expiry_info`)
- `parse_jwt` now returns a structured dict instead of tuple
- Refactored `main.py` to use Click groups (was argparse)
- Migrated from raw `print` to Rich console for colored output
- Refactored parallel brute force to use `concurrent.futures` more idiomatically
- Improved error messages throughout — most now include remediation hints

### Fixed

- `brute_force_secret` was incorrectly accepting asymmetric algorithms (false positive risk)
- `forge_token` had dead code that computed the token twice
- `verify_with_public_key` didn't handle ECDSA keys (only RSA)
- Token files with trailing newlines were failing in some edge cases
- `compare_payloads` crashed on nested dict values (now recursive)
- PII scanner produced false positives on UUIDs and base64-encoded data
- JWKS fetcher didn't respect `kid` header — always used first key
- Progress bar didn't show on non-TTY environments
- `read_token_from_file` swallowed the original exception in some error paths
- Error handling in `utils/io.py` was swallowing original exceptions
- Brute force didn't check all symmetric algorithms (only HS256)
- `diff` command crashed when payloads had nested structures

### Security

- Added confirmation prompt to `forge` command to prevent accidental misuse
- Added security warnings in `forgery.py` when using `none` algorithm
- Docker image runs as non-root user (was root by default in earlier dev builds)
- Added `SECURITY.md` with responsible disclosure policy
- Log files no longer contain raw tokens by default (only first 50 chars)
- Added `.env.example` to discourage committing secrets to `.env` directly
- PII scanner helps catch accidental credential leakage in JWT payloads

### Deprecated

- `verify_rsa` snake_case command — use `verify-rsa` instead

---
## [Unreleased]

## [1.0.0] - 2026-01-10

### Added

- Initial release
- RSA/JWK public key verification (`verify-rsa` command)
- Token forgery / modification (`forge` command)
- Automated JSON report generation (`--output` flag)
- `core/verification.py` module for public key operations
- `core/forgery.py` module for token crafting
- PyJWT 2.x compatibility
- JWT parsing and metadata extraction
- Time-sensitive validation (expiry calculation)
- `none` algorithm security check
- Brute-force secret verification with wordlist support
- Payload comparison (`diff` command)
- Modular project structure (`core/`, `utils/`)

