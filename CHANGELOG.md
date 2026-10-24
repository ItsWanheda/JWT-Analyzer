# Changelog

All notable changes to this project will be documented in this file.

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

