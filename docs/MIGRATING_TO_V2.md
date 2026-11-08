# Migrating to JWT Analyzer v2

> **Release status — UNRELEASED:** This guide documents JWT Analyzer v2.0.0 (package metadata `2.0.0.dev0`). The 2.0.0 release and Docker image have not been published. Operator review is required before production migration.

## Upgrade strategy

Treat v2 as a deliberate major-version migration. Pin the current stable 1.2.x install in production until the 2.0.0 release gates pass. Test v2 in a separate environment and compare its results against known JWT fixtures before switching automation.

## Initial Python API

The v2 import namespace is `jwt_analyzer`:

```python
from jwt_analyzer import inspect_token

assessment = inspect_token(compact_jwt)
print(assessment.to_dict())
```

`inspect_token()` only parses token structure and emits token-only indicators. It does not verify the signature, issuer, audience, or remote server behavior. Its `Assessment.verification_status` is `not_attempted`; its decoded claims remain untrusted. The original compact token is not retained in the assessment. Claims can still contain sensitive data, so do not write full assessments to shared logs or reports without an explicit redaction policy.

## M1 assessment contract and evaluation stages

The normalized result contract is schema version 1.1. `Assessment` contains decoded header and claims, cryptographic verification state, stable findings, warnings/errors, a UTC `assessed_at` timestamp, and optional policy metadata. It has no field for the original compact token. Decoded claims can still contain sensitive data, so redact them before storing or sharing assessments.

Each `Finding` includes a stable `id`, severity, confidence, category, stage, observation, impact, evidence, limitations and recommendation. IDs are machine-readable contract keys, not display labels. Findings sort by severity and then ID. The machine-readable schema is `jwt_analyzer/assessment-v1.1.schema.json`.

Signature verification and claim policy are independent stages:

```python
from pathlib import Path
from jwt_analyzer import evaluate_policy, get_policy_profile, verify_signature_with_public_key

signature_result = verify_signature_with_public_key(
    compact_jwt,
    Path("public.pem").read_text(encoding="utf-8"),
    algorithms=["RS256"],
)
assessment = evaluate_policy(
    signature_result,
    get_policy_profile(
        "strict",
        issuer="https://issuer.example",
        audience="orders-api",
    ),
)
print(assessment.to_dict())
```

`verify_signature_with_public_key()` checks the cryptographic signature only against the explicit asymmetric algorithm allowlist. `evaluate_policy()` separately evaluates the selected profile's accepted algorithms, required claims, NumericDate time claims, issuer and audience. The baseline profile requires `exp`; the strict profile also requires `iat`, `iss`, `aud` and `sub`, with a narrower algorithm allowlist. Use `AssessmentPolicy(name="organization", ...)` or `get_policy_profile("baseline", ...)` to define custom requirements.

`verification_status` describes only cryptographic signature validity. `policy["status"]` reports `passed`, `failed`, or `not_verified`. Evaluating an unverified assessment remains advisory and cannot establish token authenticity or authorize access. The convenience function `verify_with_public_key()` combines signature verification with the baseline policy while preserving this distinction.

## M2 parsing, verification, and resource boundaries

M2 adds defensive limits at the token, key, network, and CPU-intensive boundaries. These constraints are intentional; integrations should handle the resulting validation and timeout errors rather than bypassing the checks.

### JWT and JSON input

- Compact JWT input is capped at **1 MiB** and Base64URL segments must use the canonical URL-safe alphabet and encoding.
- The decoded header and payload must each be JSON objects.
- Strict JSON decoding rejects duplicate keys, non-finite numbers, invalid UTF-8, lone UTF-16 surrogates, excessive nesting, excessive node counts and integers longer than 128 digits. The structural limits are 64 nesting levels and 100,000 values.
- Valid escaped UTF-16 surrogate pairs are normalized to Unicode scalar values. Duplicate object keys created by normalization are rejected.

### Public-key and JWK verification

- Public-key/JWK input is capped at **64 KiB**.
- Verification accepts only the supported asymmetric algorithms (`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, and `EdDSA`) through an explicit allowlist.
- JWK key type and metadata must be compatible with signature verification. Private or symmetric key material is not accepted by the public-key/JWKS verification path.
- Do not select trusted algorithms from an unverified header. Continue to separate cryptographic signature state from the claim-policy result.

### Remote JWKS retrieval

JWKS retrieval is treated as an untrusted-network operation. The default path requires HTTPS, keeps certificate/hostname verification enabled, rejects redirects, validates and pins DNS answers to the connection, and enforces response and key-count limits (1 MiB and 1,000 keys). One monotonic deadline covers DNS resolution, connection, TLS negotiation and response reading. Expired cache entries are not silently used after a fetch failure.

The operating-system resolver cannot be force-cancelled portably. A timed-out lookup can occupy the single daemon resolver worker until the OS resolver returns; one pending lookup is allowed and further lookups fail closed while it is busy. See [JWKS Retrieval Security Model](JWKS_SECURITY.md).

### Bounded HMAC wordlist testing

Only HS256, HS384 and HS512 are eligible for secret wordlist testing. Candidate input is streamed and bounded by a maximum of 32 workers, 1,000,000 candidates, 4 KiB per candidate, and a 3,600-second maximum timeout. At most one candidate per worker is pending/in flight; new work stops when the deadline or candidate budget is reached.

Cancellation is cooperative. A cryptographic operation already executing in a worker cannot be safely force-interrupted; the function waits for the bounded in-flight work to finish before returning. Do not interpret a timeout as a guarantee that an individual low-level crypto call was killed at the deadline.

### Finding semantics

Findings now make an explicit distinction between confirmed local observations, likely indicators and unknown remote behavior. A token declaring `alg=none`, an unusual `kid`, or a possible algorithm/key-policy mismatch does not establish that a remote verifier accepts the attack. Confidence applies to the stated observation, not to unproven exploitability. See [M2 Security Finding Semantics](SECURITY_FINDING_SEMANTICS.md).

The M2 regression/property suite contains 46 focused tests across five modules, with an additional DNS-deadline regression in the existing JWKS security suite. The branch CI workflow passed on Python 3.9–3.14, alongside the public API, optional service security, Docker and distribution build/install checks. This is development-branch validation, not a 2.0.0 release or a guarantee that every deployment risk is eliminated.

## M3 public API, CLI, batch, and configuration contract

The current development implementation introduces the `jwt-analyzer-v2` command. It keeps the existing `jwt-analyzer` entry point intact during the transition. See [V2 API and CLI Contract](V2_API_CLI_CONTRACT.md) for the supported imports, JSON envelope, exit codes, batch format, and configuration precedence.

New automation should use `jwt-analyzer-v2 inspect --token-file ...` or `jwt-analyzer-v2 batch --input-file ...`. Batch input is one compact JWT per non-empty UTF-8 line; results are streamed as JSON Lines. A malformed item is reported independently and does not stop later items. The default batch cap is 10,000 items and may be lowered through configuration.

The public `jwt_analyzer` namespace is the compatibility boundary. Imports from `core.*`, `utils.*`, `config.Config`, or `main.py` are legacy implementation details. Public token parsing errors use `TokenAssessmentError`; configuration failures use `ConfigurationError`; batch cap failures use `BatchLimitError`.

The legacy CLI is retained in this development transition rather than silently changing its output format. The new JSON contract is a separate entry point; no legacy alias may weaken verification co## Command migration reference

The v2 CLI is a new, deliberately separate contract. The legacy jwt-analyzer entry point remains installed during this development transition; it has not been redirected to v2 JSON output. The new command is jwt-analyzer-v2.

| v1.2.x command | v2.0.0 development path | Migration notes |
|---|---|---|
| analyze --token-file token.jwt | jwt-analyzer-v2 inspect --token-file token.jwt | Both are structural inspection only. The v2 result is a versioned JSON envelope and explicitly reports verification_status=not_attempted. |
| audit --token-file token.jwt ... | Run v2 stages separately: inspect, explicitly verify when a trusted key is available, evaluate policy, then render a report. | There is intentionally no one-command v2 alias for the legacy combined audit. Do not treat inspection or policy evaluation on unverified claims as verification. |
| verify-rsa --token-file ... --public-key ... | Python API: verify_signature_with_public_key() or verify_with_public_key(). | Supply an explicit asymmetric algorithm allowlist. The v2 CLI currently has no direct verify-rsa subcommand. |
| verify-jwks --token-file ... --jwks-url ... | No supported public v2 CLI or Python API equivalent is currently exposed. The optional HTTP service accepts an inline PEM key or one public JWK, not a remote JWKS URL. | Keep the legacy remote-JWKS workflow isolated and pinned only while a reviewed migration decision is made; do not rely on internal v2 modules, pass a URL as an inline key, or disable TLS checks. |
| diff --token1 ... --token2 ... | Use the dashboard assessment-comparison workflow for normalized assessment findings. | This is not a byte-for-byte replacement for the legacy payload-diff output. Adapt consumers to the documented comparison result. |
| brute-force --token-file ... | No v2 CLI equivalent is currently provided. | The legacy command remains separate from the supported v2 CLI contract. Do not assume v2 inspect or batch performs HMAC secret recovery. |
| forge --token-file ... --payload-file ... | No v2 CLI or public API replacement is currently documented. | Keep any legacy use isolated to explicitly authorized testing and do not build new integrations against internal modules. |
| Legacy JSON/HTML output options | jwt-analyzer-v2 report --assessment-file assessment.json --format json\|html\|sarif | The v2 renderer validates the report envelope and nested Assessment; sensitive fields are redacted by default. |

### Before and after: Python API

The v1 implementation exposed parsing through internal modules. Those imports are not a stable compatibility contract:

    from core.parser import parse_jwt

    parsed = parse_jwt(compact_jwt)
    print(parsed["payload"])

Use the public v2 package for structural inspection:

    from jwt_analyzer import inspect_token

    assessment = inspect_token(compact_jwt)
    assert assessment.verification_status.value == "not_attempted"
    print(assessment.to_dict())

Inspection never verifies a signature. When signature verification is required, make that operation explicit and pass a trusted public key plus a fixed algorithm allowlist:

    from pathlib import Path
    from jwt_analyzer import verify_signature_with_public_key, evaluate_policy, get_policy_profile

    signature_result = verify_signature_with_public_key(
        compact_jwt,
        Path("issuer-public.pem").read_text(encoding="utf-8"),
        algorithms=["RS256"],
    )
    assessment = evaluate_policy(
        signature_result,
        get_policy_profile(
            "strict",
            issuer="https://issuer.example",
            audience="orders-api",
        ),
    )

Check both cryptographic verification and policy status before using claims in an application decision. A verified signature alone does not authorize a user or establish that the token is intended for this service.

### Before and after: CLI and output contract

The old analysis command emits human-oriented output:

    jwt-analyzer analyze --token-file token.jwt

The v2 inspect command emits one compact JSON document:

    jwt-analyzer-v2 inspect --token-file token.jwt > assessment.json

The envelope has CLI schema version 1, status ok, and an embedded Assessment schema version 1.1. The assessment's signature status remains not_attempted.

Batch input is UTF-8, one compact JWT per non-empty line. Each item is streamed as JSON Lines, followed by one summary line:

    jwt-analyzer-v2 batch --input-file tokens.txt > batch-results.jsonl

Render a previously saved assessment with the shared v2 reporting engine:

    jwt-analyzer-v2 report --assessment-file assessment.json --format sarif --output findings.sarif

Supported report formats are JSON, HTML, and SARIF. JSON report envelope schema is 1.0; the embedded Assessment is schema 1.1; SARIF is validated against 2.1.0. Redaction is on by default. The --include-sensitive option deliberately disables report redaction and should only be used for controlled local output.

The v2 CLI exit codes are:

| Exit code | Meaning |
|---:|---|
| 0 | Requested work completed successfully |
| 1 | A token assessment failed or a batch was partial, or the configured report threshold was reached |
| 2 | CLI usage, file input, configuration, batch-limit, or report validation error |

Successful machine-readable results go to stdout. Structured error envelopes go to stderr. Do not parse the legacy CLI's human-oriented output as the v2 JSON contract.

### Configuration migration

The v2 JSON/YAML configuration file is limited to 1 MiB, uses safe YAML parsing, rejects unknown keys, and applies precedence in this order: defaults, configuration file, environment.

Example YAML configuration:

    policy: strict
    policy_options:
      issuer: https://issuer.example
      audience: orders-api
      require_issuer: true
      require_audience: true
      leeway_seconds: 30
    max_batch_items: 2500
    wordlist_path: ./wordlists/custom.txt
    fail_on_severity: high

The v2 environment variables are:

| Variable | v2 meaning | Default / constraint |
|---|---|---|
| JWT_ANALYZER_POLICY | Policy profile name | baseline; supported profile names are validated |
| JWT_ANALYZER_MAX_BATCH_ITEMS | Maximum non-empty batch items | 10000; positive integer |
| JWT_ANALYZER_WORDLIST_PATH | Configured wordlist path | Optional path; this variable is also recognized by the legacy configuration |
| JWT_ANALYZER_FAIL_ON_SEVERITY | Report/CI severity threshold | high; one of none, info, low, medium, high, critical |

The policy options currently accepted under policy_options are accepted_algorithms, required_claims, time_claims, issuer, audience, require_issuer, require_audience, leeway_seconds, and max_future_iat_seconds.

Legacy environment variables JWT_ANALYZER_TIMEOUT, JWT_ANALYZER_LOG_LEVEL, and JWT_ANALYZER_ENABLE_RICH are not v2 configuration keys. The v2 command uses structured machine-readable output; do not expect Rich formatting or the legacy brute-force timeout setting to affect it. The legacy JWT_ANALYZER_WORDLIST_PATH continues to be recognized.

### Reports, plugins, and optional service

- The v2 public API uses the jwt_analyzer namespace. Imports from core.*, utils.*, the repository-root config.Config, and direct main.py imports are implementation details, not the v2 compatibility promise.
- JSON, HTML, and SARIF reports share the normalized Assessment model. Redaction is enabled by default; sensitive values require explicit opt-in.
- The optional HTTP service and dashboard are installed with the service extra and require CPython 3.10–3.14. The core CLI/API continue to support Python 3.9–3.14. Python 3.9 deliberately does not install the service framework dependencies because the patched Starlette line requires Python 3.10 or newer; the service refuses to start there rather than falling back to the vulnerable pre-1.0 framework line. The service is loopback-first and has explicit Host, bearer-authentication, request-size, rate, concurrency, and request-lifetime controls. Remote mode requires deliberate operator configuration and a TLS-terminating proxy or private access-controlled network.
- The v2 plugin contract uses the jwt_analyzer.plugins.v2 entry-point group and explicit operator enablement. Plugins execute as trusted in-process Python code; they are not sandboxed. The legacy directory-based plugin loader is disabled. Audit every plugin package before enabling it.

### Removal and compatibility table

| Surface | v2.0.0 development status | Operator action |
|---|---|---|
| Legacy jwt-analyzer command group | Retained as a separate compatibility path during development; not a v2 JSON contract | Keep legacy automation pinned until migrated and tested |
| Legacy internal Python imports (core.*, utils.*, config.Config) | Not a supported v2 API | Move new integrations to documented jwt_analyzer exports |
| Legacy directory-scanning plugin loader | Disabled | Port plugins to the versioned entry-point contract and enable them explicitly |
| Implicit signature trust from decoded claims | Not supported | Require explicit verification and application policy |
| Unredacted report output by default | Not supported by v2 reporting | Use redacted exports; sensitive output requires an explicit opt-in |
| v2 CLI commands for brute-force, forge, verify-rsa, verify-jwks, and combined audit | No direct command replacement currently exists | Keep these workflows separate; do not invent aliases or infer that inspect performs them |

No blanket removal of the legacy CLI is performed by this development branch. Any future removal requires a separately announced deprecation period, a versioning decision, and updated migration documentation.


## Before production cutover

- [ ] Read the final `2.0.0` changelog and resolve every breaking-change entry.
- [ ] Run the full test suite and the clean-install matrix on supported Python versions.
- [ ] Compare JSON/HTML/SARIF reports and CI exit codes for representative tokens.
- [ ] Exercise valid, expired, malformed, wrong-key, wrong-algorithm, wrong-issuer and wrong-audience cases.
- [ ] Verify that token material, signing secrets and sensitive claims are not leaking to logs or artifacts.
- [ ] Test rollback to the pinned 1.2.x installation and preserve a copy of the prior config/report parsers.

Before production migration, an operator must confirm the command/API/configuration mapping against the release commit, the independent security review must be recorded, and the release checklist must be approved. Keep the existing 1.2.x deployment pinned until those steps and the formal v2.0.0 release are complete.
