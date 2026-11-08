# JWT Analyzer 2.0.0 — Release Notes (Draft)

> **Status: NOT RELEASED.** This is a draft for the M7 release candidate. The repository version remains 2.0.0.dev0. No PyPI publication, Docker push, release tag, or production approval is implied.

## Highlights

### Normalized assessment model and explicit verification

- Introduces the public jwt_analyzer Python namespace and a versioned Assessment/Finding contract (Assessment schema 1.1).
- Separates structural inspection, cryptographic signature verification, and claim-policy evaluation. Structural inspection does not verify a signature; claims remain untrusted until verification and application policy checks are completed.
- Provides stable finding identifiers, severity/confidence metadata, evidence, limitations and recommendations to support programmatic integrations.

### Defensive parsing and verification boundaries

- Applies bounded JWT, JSON, key/JWK, network, and HMAC wordlist inputs.
- Uses strict JSON parsing, canonical Base64URL validation, duplicate-key rejection and structural resource caps.
- Restricts public-key verification to an explicit asymmetric algorithm allowlist.
- Hardens remote JWKS retrieval with HTTPS/TLS verification, DNS answer validation and connection pinning, redirect rejection, bounded response/key counts, cache controls and a monotonic deadline.
- Describes token-only findings as indicators where remote verifier behavior has not been established.

### Versioned CLI, batch processing and configuration

- Adds the separate jwt-analyzer-v2 CLI with machine-readable JSON output, structured JSON errors and documented exit codes.
- Adds streamed newline-delimited batch assessment with per-item outcomes and a configurable upper bound.
- Adds validated JSON/YAML configuration with safe YAML parsing, a size limit, unknown-key rejection, and defaults < file < environment precedence.
- Keeps the legacy jwt-analyzer command as a separate transition path; its output is not silently converted into the v2 JSON envelope.

### Reporting, optional service and dashboard

- Adds schema-validated JSON report envelope v1.0, HTML reports and SARIF 2.1.0 output.
- Redacts sensitive values by default; including sensitive data requires an explicit opt-in.
- Adds an optional HTTP service with health/readiness endpoints, bearer authentication, request limits, rate/concurrency controls and safe structured errors.
- Adds a same-origin dashboard for local token selection/paste, inspect and explicit public-key verification workflows, comparison and report export. Browser state is not persisted by default.

### Plugin ecosystem

- Adds a versioned plugin entry-point contract, metadata-only discovery, explicit enablement, capability checks, namespaced findings, deterministic execution and exception isolation.
- The legacy working-directory plugin loader is disabled.
- Plugins execute as trusted in-process Python code. They are not sandboxed and must be reviewed before enablement.

## Compatibility and migration

This is a major-version transition. Read the complete migration guide before changing production automation:

- v1.2.x internal imports such as core.* and utils.* are not the v2 compatibility boundary. New integrations should use the public jwt_analyzer namespace.
- The v2 CLI is separate from the legacy CLI. New automation should adopt jwt-analyzer-v2 and its documented JSON contract.
- There is no direct v2 CLI replacement for the legacy combined audit, remote verify-jwks, brute-force, or forge commands. Do not assume inspect or batch performs signature verification, remote JWKS retrieval, secret recovery or token forging.
- The new report envelopes and schemas differ from legacy output. Update downstream parsers and CI thresholds explicitly.
- The legacy directory-scanning plugin loader is disabled. Port plugins to the versioned entry-point contract and enable them deliberately.
- Configuration variables and precedence differ. Review the mapping in docs/MIGRATING_TO_V2.md rather than copying all v1 environment variables into v2.

See docs/MIGRATING_TO_V2.md for exact examples and documented non-equivalents.

## Supported runtime

The package metadata declares CPython 3.9–3.14. The M7 workflow checks editable, wheel and source-distribution installation on Linux, Windows and macOS. The release should not claim the full matrix as verified until the workflow run for the exact release commit is green and archived.

## Known limitations at candidate preparation

- Version 2.0.0 is still development software until M7 acceptance and explicit maintainer approval.
- A successful structural inspection is not signature verification or authorization.
- Policy evaluation on unverified claims remains advisory.
- The v2 CLI currently does not provide direct subcommands for remote JWKS verification, brute-force, token forging, or a one-command combined legacy audit.
- The HTTP service is optional and should remain loopback-first unless remote exposure is deliberately configured with authentication, Host validation and protected transport.
- Plugin code runs in the analyzer process without a sandbox, timeout isolation or separate OS security boundary.
- M6-05 and M7 acceptance remain pending until final CI evidence, independent security review and operator migration review are recorded.

## Installation

Do not use the following commands until the 2.0.0 release is published and the release artifacts have been verified.

Standard package:

    python -m pip install "jwt-analyzer==2.0.0"

Optional HTTP service and dashboard:

    python -m pip install "jwt-analyzer[service]==2.0.0"

For a controlled candidate test before publication, install the locally built wheel only after verifying its SHA-256 manifest and GitHub attestations. Follow docs/RELEASE_CHECKLIST.md.

## Upgrade and rollback

Upgrade only after the v1.2.x artifact, configuration and report parsers have been backed up. Test v2 in a separate environment, map the old commands and environment variables, validate representative tokens and outputs, and obtain operator/security approval before production cutover.

Rollback by redeploying the exact pinned v1.2.x wheel or immutable container digest and restoring the saved v1 configuration, commands and report parsers. Do not attempt rollback by changing only the version string.

## Release authorization

**Maintainer approval:** pending  
**Independent security reviewer:** pending  
**Release commit:** pending  
**Tag:** not created  
**PyPI publication:** not performed  
**Docker publication:** not performed
