# JWT Analyzer 2.0.0 — Release Notes

> **Release status — STABLE SOURCE RELEASE.** JWT Analyzer v2.0.0 was integrated into `main` on 2026-11-08 (merge commit `3ee1bd37d063bb3cd042572693ae98a12fc7e1c9`). The acceptance reviews are complete per maintainer confirmation. PyPI/Docker artifact publication and the corresponding tag are separate distribution actions.

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

The core CLI and Python API support CPython 3.9–3.14. The optional HTTP service/dashboard requires CPython 3.10–3.14 because supported, patched FastAPI/Starlette releases no longer support Python 3.9. The M7 workflow passed on source commit `a2640e98e9c420b4c0ff2ec33b49c9c5c7932904`: [full CI run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094) (33/33 jobs), covering editable/wheel/sdist installs on Linux, Windows and macOS × CPython 3.9–3.14, plus separate service security tests on Python 3.10–3.14.

## M7 build and validation evidence

The v2.0.0 source and packaging workflows have passed the recorded technical validation:

- Full CI: [run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094), 33/33 jobs successful on commit `a2640e98`. This includes the six-version core matrix, five-version optional-service matrix, 18 cross-platform install combinations, quality checks, Chromium dashboard E2E, clean distribution installs and Docker validation.
- Supply chain: [run #42502255064](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255064), successful on commit `a2640e98`. Dependency audit, CycloneDX SBOM, repeat-build digest comparison, SLSA provenance attestations and CycloneDX SBOM attestations passed; provenance and SBOM predicates were verified against the expected repository and signer workflow.
- The downloaded supply-chain artifact manifest was checked against all four files. It records 88 audited dependency components and zero known advisories. Wheel SHA-256: `a691121a7ea12cf6012b4c0cc71691ea3ca3667876e75dddfcc8c66c32494614`; sdist SHA-256: `9f3069368cdc5869efe9109358c595f3d1301f548e2738dc5645ce9ef636e993`; CycloneDX SBOM SHA-256: `4b4fad96f126f50059ef3689df834c1f6bd8c97ae01765245abbac7da6e58364`; build record SHA-256: `2e2dd45760950188c59853a50a5856022929799c884414158227c967f1f66bad`.
- Repeat-build equality is limited to two builds of the same source commit on one hosted runner with the same toolchain and `SOURCE_DATE_EPOCH`. It is not an independent or cross-platform reproducibility claim.

These are candidate build artifacts retained as CI evidence, not registry release assets. The migration guide and release checklist have been reviewed and approved as confirmed by the project maintainer. Do not infer PyPI or Docker publication from workflow artifact retention.

## Known limitations

- Version 2.0.0 is the stable source release. Follow the security, configuration, and plugin trust-boundary guidance in this document.
- A successful structural inspection is not signature verification or authorization.
- Policy evaluation on unverified claims remains advisory.
- The v2 CLI currently does not provide direct subcommands for remote JWKS verification, brute-force, token forging, or a one-command combined legacy audit.
- The HTTP service is optional and should remain loopback-first unless remote exposure is deliberately configured with authentication, Host validation and protected transport.
- Plugin code runs in the analyzer process without a sandbox, timeout isolation or separate OS security boundary.
- M7-01 operator migration review, M7-04 independent security review, and M7-05 maintainer/operator approval are complete per maintainer confirmation dated 2026-11-08. M7-02 and M7-03 technical validation passed on the recorded candidate commits listed below.

## Installation

Use the following commands only when the `2.0.0` package is available from the configured package index and the downloaded artifact has been verified. For offline or staged deployments, install the locally built wheel after digest and attestation verification.

Standard package:

    python -m pip install "jwt-analyzer==2.0.0"

Optional HTTP service and dashboard:

    python -m pip install "jwt-analyzer[service]==2.0.0"

For controlled or offline installation, use the locally built wheel only after verifying its SHA-256 manifest and GitHub attestations. Follow docs/RELEASE_CHECKLIST.md.

## Upgrade and rollback

Upgrade only after the v1.2.x artifact, configuration and report parsers have been backed up. Test v2 in a separate environment, map the old commands and environment variables, validate representative tokens and outputs, and obtain operator/security approval before production cutover.

Rollback by redeploying the exact pinned v1.2.x wheel or immutable container digest and restoring the saved v1 configuration, commands and report parsers. Do not attempt rollback by changing only the version string.

## Release authorization

**Maintainer approval:** completed (maintainer confirmation, 2026-11-08)  
**Independent security review:** completed (maintainer confirmation, 2026-11-08; reviewer identity not mirrored in this public summary)  
**Source integration commit:** `3ee1bd37d063bb3cd042572693ae98a12fc7e1c9`  
**Stable Git tag:** not created by this source-documentation update  
**PyPI publication:** not performed by this source-documentation update  
**Docker publication:** not performed by this source-documentation update
