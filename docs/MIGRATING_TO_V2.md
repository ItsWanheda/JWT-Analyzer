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
