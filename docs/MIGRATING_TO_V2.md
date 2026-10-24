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

## Before production cutover

- [ ] Read the final `2.0.0` changelog and resolve every breaking-change entry.
- [ ] Run the full test suite and the clean-install matrix on supported Python versions.
- [ ] Compare JSON/HTML/SARIF reports and CI exit codes for representative tokens.
- [ ] Exercise valid, expired, malformed, wrong-key, wrong-algorithm, wrong-issuer and wrong-audience cases.
- [ ] Verify that token material, signing secrets and sensitive claims are not leaking to logs or artifacts.
- [ ] Test rollback to the pinned 1.2.x installation and preserve a copy of the prior config/report parsers.

The migration guide is not complete until these steps have been exercised against the release candidate and the exact removed/renamed interfaces are documented.
