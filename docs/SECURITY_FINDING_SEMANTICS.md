# M2 Security Finding Semantics

This document is the rule-level calibration reference for the v2 inspection and policy engine. A finding describes the evidence the analyzer actually observed. It must not claim that a remote verifier is vulnerable unless that behavior was independently exercised and reproduced.

## Evidence and confidence vocabulary

| Evidence class | Meaning | Confidence guidance |
| --- | --- | --- |
| Confirmed local fact | Directly decoded or measured from the supplied token, key, response, or local configuration. | High confidence in the local observation only. |
| Likely indicator | A heuristic pattern is present, but several benign or alternate explanations remain possible. | Low or medium confidence; state the heuristic and its limitations. |
| Unknown remote behavior | The analyzer has not tested the target verifier or server-side key-selection path. | Do not assign confidence that the remote system is vulnerable. State that it remains unknown. |

Confidence measures certainty in the stated observation, not exploitability. Severity measures potential impact if a verifier or application exhibits the behavior described. Neither score establishes that an external target is affected.

## Inspection rules

| Stable finding ID | Observation | Default severity | Confidence | Evidence required | Explicit limitation |
| --- | --- | --- | --- | --- | --- |
| `jwt.algorithm.none_declared` | The decoded header contains `alg=none`. | Medium | High | Header algorithm and whether a signature segment is present. | This does not prove that any verifier accepts unsigned tokens. |
| `jwt.algorithm.missing` | The header has no non-empty string algorithm. | Low | High | Header field type. | This describes the supplied header, not remote verifier behavior. |
| `jwt.claim.exp_missing` | The decoded payload has no `exp` claim. | Medium | High | Presence/absence of the claim. | Whether a verifier requires expiry is unknown until its policy is checked. |
| `jwt.header.kid_suspicious_indicator` | A `kid` string matches a known suspicious-input pattern. | Low | Low | Matched heuristic indicators only; do not expose unbounded values. | Pattern matching does not prove SQL, path, or command injection. |

These are token observations. They remain useful even when the token has not been verified, but decoded claim values remain attacker-controlled. Valid escaped UTF-16 surrogate pairs in JSON are normalized to Unicode scalar values; lone surrogates and keys that collide after normalization are rejected.

## Claim-policy rules

Policy findings are conditional on the selected local policy profile. They do not replace authorization checks.

| Stable finding ID | Policy condition | Default severity | Confidence after valid signature | Confidence before signature verification |
| --- | --- | --- | --- | --- |
| `jwt.policy.algorithm_missing` | Header algorithm is absent or invalid. | High | High | Medium |
| `jwt.policy.algorithm_not_allowed` | Header algorithm is outside the policy allowlist. | High | High | Medium |
| `jwt.policy.claim_missing.*` | A configured required claim is absent or empty. | Medium | High | Medium |
| `jwt.policy.time_claim_invalid.*` | A configured time claim is not a finite NumericDate. | Medium | High | Medium |
| `jwt.policy.token_expired` | `exp` is at or before the policy-adjusted time. | High | High | Medium |
| `jwt.policy.token_not_yet_valid` | `nbf` is later than the policy-adjusted time. | Medium | High | Medium |
| `jwt.policy.issued_in_future` | `iat` exceeds the configured future-time tolerance. | Medium | High | Medium |
| `jwt.policy.issuer_missing` | The profile requires a non-empty string `iss`. | Medium | High | Medium |
| `jwt.policy.issuer_mismatch` | `iss` differs from the configured issuer. | High | High | Medium |
| `jwt.policy.audience_missing` | The profile requires a valid `aud` value. | Medium | High | Medium |
| `jwt.policy.audience_mismatch` | `aud` does not contain the configured audience. | High | High | Medium |

Before verification, policy evaluation is explicitly advisory and reports `policy.status=not_verified` with `compliant=null`. A policy match on unverified claims is not proof of authenticity. After signature verification, policy findings describe conformance to the local issuer, audience, time, required-claim, and algorithm rules; they still do not prove application authorization.

## Verification and network failures

Invalid signatures, malformed keys, incompatible JWK metadata, ambiguous JWKS key IDs, TLS failures, DNS-policy failures, redirects, and response-limit failures are represented as verification or retrieval errors/statuses. They are not automatically promoted to remote vulnerability findings. A failed defensive check means the analyzer could not safely complete that operation; it is not evidence that the remote service is exploitable.

## Evidence and remediation requirements

Every finding must keep a stable machine-readable ID and include:

- an observation that can be traced to the supplied input or selected policy;
- evidence sufficient to reproduce that observation, without copying private keys or signing secrets;
- impact phrased conditionally where remote behavior is unknown;
- limitations that state what was not tested or established; and
- actionable remediation that does not recommend weakening algorithm, TLS, destination, input-size, or redaction controls.

Tests in `tests/test_m2_finding_semantics.py` enforce the critical distinctions between confirmed local facts, low-confidence heuristics, unverified policy indicators, and verified-signature policy mismatches.
