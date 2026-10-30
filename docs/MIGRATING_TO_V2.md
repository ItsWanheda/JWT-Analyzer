# Migrating to JWT Analyzer v2

> **Status:** work in progress. `2.0.0.dev0` is not a production release and is not published to PyPI or Docker. This document will be finalized before any 2.0.0 release.

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

## Planned breaking changes

The list below is the migration checklist; entries will be replaced with exact old/new examples as the implementation stabilizes.

| Area | v1 behavior | v2 direction | Migration action |
|---|---|---|---|
| Python imports | Import internal modules such as `core.*` | Public `jwt_analyzer` namespace | Switch callers to documented public exports; avoid depending on `core` internals |
| Assessment data | Ad-hoc dictionaries vary by command | Versioned `Assessment` / `Finding` schema | Update code to consume schema version and stable finding IDs |
| Verification | Decode and verification commands are separate but their outputs vary | Explicit `not_attempted`, `verified`, `invalid`, or `error` status | Never infer verification from decoded claims; branch on the explicit status |
| Heuristic findings | Some messages may imply confirmed exploitability from token-only patterns | Indicators document evidence and limitations | Update alert thresholds and confirm target behavior independently |
| CLI output | Existing JSON/HTML fields and exit behavior | Stable versioned output and documented exit-code policy | Update parsers and CI thresholds after the v2 CLI contract is finalized |
| JWKS flags | Older examples may reference disabling TLS verification | TLS verification remains enabled | Remove `--no-verify-ssl` usage; fix trust roots/certificates instead |
| Plugins | Legacy `plugins/` loader and implicit `register()` discovery | Explicitly enabled, versioned plugin interface | Do not rely on auto-discovery semantics; review each plugin's trust boundary |
| Configuration | Existing YAML/environment keys | Validated, documented policy/config schema | Validate and migrate config before rollout |
| HTTP service | Not part of the v1 CLI-only contract | Optional `jwt-analyzer[service]` extra; loopback-first API and dashboard | Install the extra explicitly; review bearer auth, Host allowlist, request caps and reverse-proxy/TLS configuration before enabling network access |

## Before production cutover

- [ ] Read the final `2.0.0` changelog and resolve every breaking-change entry.
- [ ] Run the full test suite and the clean-install matrix on supported Python versions.
- [ ] Compare JSON/HTML/SARIF reports and CI exit codes for representative tokens.
- [ ] Exercise valid, expired, malformed, wrong-key, wrong-algorithm, wrong-issuer and wrong-audience cases.
- [ ] Verify that token material, signing secrets and sensitive claims are not leaking to logs or artifacts.
- [ ] Test rollback to the pinned 1.2.x installation and preserve a copy of the prior config/report parsers.

The migration guide is not complete until these steps have been exercised against the release candidate and the exact removed/renamed interfaces are documented.
