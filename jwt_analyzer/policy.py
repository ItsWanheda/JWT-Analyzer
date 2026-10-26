"""Application claim-policy profiles, separate from parsing and signature checks."""

from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, replace
from typing import Any

from .models import Assessment, Confidence, Finding, Severity, VerificationStatus

DEFAULT_ASYMMETRIC_ALGORITHMS = (
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"
)
STRICT_ALGORITHMS = ("RS256", "ES256", "EdDSA")
KNOWN_ALGORITHMS = frozenset(
    {
        "HS256", "HS384", "HS512",
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512", "EdDSA",
    }
)
_UNVERIFIED_POLICY_WARNING = (
    "Policy checks evaluated decoded, unverified claims; these results are advisory "
    "and are not an authentication or authorization decision."
)


@dataclass(frozen=True)
class AssessmentPolicy:
    """User-defined policy constraints applied after parsing and/or signature checks.

    now_timestamp is an optional deterministic test/control hook for reproducible
    policy evaluation against a fixed clock.
    """

    name: str = "custom"
    accepted_algorithms: tuple[str, ...] = DEFAULT_ASYMMETRIC_ALGORITHMS
    required_claims: tuple[str, ...] = ("exp",)
    time_claims: tuple[str, ...] = ("exp", "nbf", "iat")
    issuer: str | None = None
    audience: str | None = None
    require_issuer: bool = False
    require_audience: bool = False
    leeway_seconds: float = 0.0
    max_future_iat_seconds: float = 0.0
    now_timestamp: float | None = None

    def __post_init__(self) -> None:
        _normalize_policy(self)


def _normalize_string_sequence(field_name: str, value: Any) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise TypeError(f"{field_name} must be a sequence of strings")
    normalized = tuple(value)
    if any(not isinstance(item, str) or not item.strip() for item in normalized):
        raise ValueError(f"{field_name} must contain non-empty strings")
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field_name} must not contain duplicates")
    return normalized


def _finite_number(name: str, value: Any, *, non_negative: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite number")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError(f"{name} must be a finite number")
    if non_negative and normalized < 0:
        raise ValueError(f"{name} must be non-negative")
    return normalized


def _normalize_policy(policy: AssessmentPolicy) -> None:
    if not isinstance(policy.name, str):
        raise TypeError("policy name must be a string")
    if not policy.name.strip():
        raise ValueError("policy name must be a non-empty string")
    for field_name in ("accepted_algorithms", "required_claims", "time_claims"):
        normalized = _normalize_string_sequence(field_name, getattr(policy, field_name))
        object.__setattr__(policy, field_name, normalized)
    if not policy.accepted_algorithms:
        raise ValueError("accepted_algorithms must not be empty")
    unsupported = sorted(set(policy.accepted_algorithms).difference(KNOWN_ALGORITHMS))
    if unsupported:
        raise ValueError("unsupported algorithm name(s): " + ", ".join(unsupported))
    if any(claim not in {"exp", "nbf", "iat"} for claim in policy.time_claims):
        raise ValueError("time_claims may contain only exp, nbf, and iat")
    for field_name in ("issuer", "audience"):
        value = getattr(policy, field_name)
        if value is not None and not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string when configured")
        if value is not None and not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string when configured")
    if not isinstance(policy.require_issuer, bool) or not isinstance(
        policy.require_audience, bool
    ):
        raise TypeError("require_issuer and require_audience must be booleans")
    for field_name in ("leeway_seconds", "max_future_iat_seconds"):
        normalized = _finite_number(
            field_name, getattr(policy, field_name), non_negative=True
        )
        object.__setattr__(policy, field_name, normalized)
    if policy.now_timestamp is not None:
        normalized_now = _finite_number("now_timestamp", policy.now_timestamp)
        object.__setattr__(policy, "now_timestamp", normalized_now)



_BASELINE = AssessmentPolicy(name="baseline")
_STRICT = AssessmentPolicy(
    name="strict",
    accepted_algorithms=STRICT_ALGORITHMS,
    required_claims=("exp", "iat", "iss", "aud", "sub"),
    require_issuer=True,
    require_audience=True,
)


def get_policy_profile(name: str = "baseline", **overrides: Any) -> AssessmentPolicy:
    """Return a named profile with optional validated overrides.

    For organization-specific settings, construct AssessmentPolicy(name=..., ...)
    directly or use get_policy_profile("baseline", ...) as a starting point.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("profile name must be a non-empty string")
    if name == "baseline":
        profile = _BASELINE
    elif name == "strict":
        profile = _STRICT
    elif name == "custom":
        profile = replace(_BASELINE, name="custom")
    else:
        raise ValueError("unknown policy profile; choose baseline, strict, or custom")
    if "name" in overrides:
        raise ValueError("profile name is set by the profile selector")
    return replace(profile, **overrides)


def baseline_policy(**overrides: Any) -> AssessmentPolicy:
    """Build the baseline profile, optionally overriding organization settings."""
    return get_policy_profile("baseline", **overrides)


def strict_policy(**overrides: Any) -> AssessmentPolicy:
    """Build the strict profile, optionally overriding organization settings."""
    return get_policy_profile("strict", **overrides)


def _claim_slug(claim: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", claim.casefold()).strip("_")[:32] or "claim"
    digest = hashlib.sha256(claim.encode("utf-8")).hexdigest()[:8]
    return f"{slug}.{digest}"


def _is_present(value: Any) -> bool:
    return value is not None and value not in ("", [])


def _valid_audience(value: Any) -> tuple[bool, set[str]]:
    if isinstance(value, str) and value:
        return True, {value}
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return True, set(value)
    return False, set()


def _policy_finding(
    *,
    finding_id: str,
    title: str,
    observation: str,
    severity: Severity,
    confidence: Confidence,
    impact: str,
    recommendation: str,
    evidence: dict[str, Any],
    verified_claims: bool,
) -> Finding:
    if verified_claims:
        limitations = (
            "This finding describes conformance to the selected local policy; it does not "
            "replace application authorization checks or prove remote verifier behavior."
        )
    else:
        limitations = (
            "The claim values have not passed cryptographic verification. This is a policy "
            "indicator only and must not be used as an authentication or authorization decision."
        )
    return Finding(
        id=finding_id,
        title=title,
        description=observation,
        severity=severity,
        confidence=confidence,
        category="claim-policy",
        recommendation=recommendation,
        evidence=evidence,
        observation=observation,
        impact=impact,
        limitations=limitations,
        stage="policy",
    )


def _evaluate_algorithm(
    assessment: Assessment,
    policy: AssessmentPolicy,
    confidence: Confidence,
    verified: bool,
) -> list[Finding]:
    algorithm = assessment.header.get("alg")
    if not isinstance(algorithm, str) or not algorithm:
        return [
            _policy_finding(
                finding_id="jwt.policy.algorithm_missing",
                title="Algorithm is missing or invalid",
                observation="The token header does not declare a non-empty algorithm name.",
                severity=Severity.HIGH,
                confidence=confidence,
                impact="A verifier cannot safely select an expected signature algorithm.",
                recommendation="Reject the token and configure an explicit algorithm allowlist.",
                evidence={"header_field": "alg"},
                verified_claims=verified,
            )
        ]
    if algorithm not in policy.accepted_algorithms:
        return [
            _policy_finding(
                finding_id="jwt.policy.algorithm_not_allowed",
                title="Algorithm is not allowed by policy",
                observation="The declared algorithm is outside the selected policy allowlist.",
                severity=Severity.HIGH,
                confidence=confidence,
                impact="A verifier following this policy must reject tokens using this algorithm.",
                recommendation=(
                    "Use an explicitly configured algorithm supported by the issuer and verifier."
                ),
                evidence={
                    "algorithm": algorithm,
                    "accepted_algorithms": list(policy.accepted_algorithms),
                },
                verified_claims=verified,
            )
        ]
    return []


def _evaluate_required_claims(
    claims: dict[str, Any] | Any,
    policy: AssessmentPolicy,
    confidence: Confidence,
    verified: bool,
) -> list[Finding]:
    findings = []
    for claim in policy.required_claims:
        if claim not in claims or not _is_present(claims.get(claim)):
            findings.append(
                _policy_finding(
                    finding_id=f"jwt.policy.claim_missing.{_claim_slug(claim)}",
                    title="Required claim is missing",
                    observation=f"The selected policy requires the {claim!r} claim.",
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    impact=(
                        "The token does not satisfy a required field in the "
                        "configured claim policy."
                    ),
                    recommendation=(
                        f"Configure the issuer to provide a valid {claim!r} claim or revise "
                        "the policy deliberately."
                    ),
                    evidence={"claim": claim, "profile": policy.name},
                    verified_claims=verified,
                )
            )
    return findings


def _numeric_timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _evaluate_time_claims(
    claims: dict[str, Any] | Any,
    policy: AssessmentPolicy,
    now: float,
    confidence: Confidence,
    verified: bool,
) -> list[Finding]:
    findings = []
    leeway = policy.leeway_seconds
    for claim in policy.time_claims:
        if claim not in claims:
            continue
        numeric_value = _numeric_timestamp(claims[claim])
        if numeric_value is None:
            findings.append(
                _policy_finding(
                    finding_id=f"jwt.policy.time_claim_invalid.{claim}",
                    title="Time claim has an invalid type or value",
                    observation=f"The {claim!r} claim must be a finite numeric timestamp.",
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    impact="Malformed time claims can cause inconsistent token-lifetime decisions.",
                    recommendation=f"Emit a finite NumericDate value for the {claim!r} claim.",
                    evidence={"claim": claim, "reason": "expected_finite_numeric_date"},
                    verified_claims=verified,
                )
            )
            continue
        if claim == "exp" and numeric_value <= now - leeway:
            findings.append(
                _policy_finding(
                    finding_id="jwt.policy.token_expired",
                    title="Token is expired under policy",
                    observation=(
                        "The exp timestamp is at or before the policy-adjusted current time."
                    ),
                    severity=Severity.HIGH,
                    confidence=confidence,
                    impact="A verifier enforcing this policy must reject an expired token.",
                    recommendation=(
                        "Obtain a newly issued token; do not extend expiry by mutating a token."
                    ),
                    evidence={"claim": "exp", "leeway_seconds": leeway},
                    verified_claims=verified,
                )
            )
        elif claim == "nbf" and numeric_value > now + leeway:
            findings.append(
                _policy_finding(
                    finding_id="jwt.policy.token_not_yet_valid",
                    title="Token is not yet valid under policy",
                    observation=(
                        "The nbf timestamp is later than the policy-adjusted current time."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    impact="A verifier enforcing this policy should not accept the token yet.",
                    recommendation="Check issuer clock synchronization and token activation time.",
                    evidence={"claim": "nbf", "leeway_seconds": leeway},
                    verified_claims=verified,
                )
            )
        elif claim == "iat" and numeric_value > (
            now + leeway + policy.max_future_iat_seconds
        ):
            findings.append(
                _policy_finding(
                    finding_id="jwt.policy.issued_in_future",
                    title="Issued-at time is in the future",
                    observation="The iat timestamp exceeds the configured future-time tolerance.",
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    impact=(
                        "Unexpected future issuance times can indicate clock skew or "
                        "malformed claims."
                    ),
                    recommendation=(
                        "Check issuer clock synchronization and the configured tolerance."
                    ),
                    evidence={
                        "claim": "iat",
                        "max_future_iat_seconds": policy.max_future_iat_seconds,
                    },
                    verified_claims=verified,
                )
            )
    return findings


def _evaluate_issuer_audience(
    claims: dict[str, Any] | Any,
    policy: AssessmentPolicy,
    confidence: Confidence,
    verified: bool,
) -> list[Finding]:
    findings = []
    issuer_value = claims.get("iss")
    if policy.require_issuer and not (isinstance(issuer_value, str) and issuer_value):
        findings.append(
            _policy_finding(
                finding_id="jwt.policy.issuer_missing",
                title="Issuer claim is required",
                observation="The selected policy requires a non-empty string iss claim.",
                severity=Severity.MEDIUM,
                confidence=confidence,
                impact="The token's issuing authority cannot be identified under this policy.",
                recommendation=(
                    "Require an issuer claim and validate it against a configured trusted issuer."
                ),
                evidence={"claim": "iss"},
                verified_claims=verified,
            )
        )
    elif policy.issuer is not None and issuer_value != policy.issuer:
        findings.append(
            _policy_finding(
                finding_id="jwt.policy.issuer_mismatch",
                title="Issuer does not match policy",
                observation="The iss claim does not equal the configured trusted issuer.",
                severity=Severity.HIGH,
                confidence=confidence,
                impact="A verifier enforcing the configured issuer must reject this token.",
                recommendation=(
                    "Use the expected issuer value and validate it during policy evaluation."
                ),
                evidence={"claim": "iss", "expected_value_disclosed": False},
                verified_claims=verified,
            )
        )

    audience_present, audience_values = _valid_audience(claims.get("aud"))
    if policy.require_audience and not audience_present:
        findings.append(
            _policy_finding(
                finding_id="jwt.policy.audience_missing",
                title="Audience claim is required",
                observation=(
                    "The selected policy requires a non-empty string or string-array aud claim."
                ),
                severity=Severity.MEDIUM,
                confidence=confidence,
                impact=(
                    "The intended recipient of the token cannot be established under this policy."
                ),
                recommendation=(
                    "Require and validate an audience matching the receiving application."
                ),
                evidence={"claim": "aud"},
                verified_claims=verified,
            )
        )
    elif policy.audience is not None and policy.audience not in audience_values:
        findings.append(
            _policy_finding(
                finding_id="jwt.policy.audience_mismatch",
                title="Audience does not match policy",
                observation="The aud claim does not include the configured expected audience.",
                severity=Severity.HIGH,
                confidence=confidence,
                impact="A verifier enforcing the configured audience must reject this token.",
                recommendation=(
                    "Use the expected audience and validate it for the receiving application."
                ),
                evidence={"claim": "aud", "expected_value_disclosed": False},
                verified_claims=verified,
            )
        )
    return findings


def evaluate_policy(
    assessment: Assessment,
    policy: AssessmentPolicy | str = "baseline",
) -> Assessment:
    """Evaluate policy separately without changing cryptographic verification status.

    Unverified claims can be evaluated for diagnostics, but the resulting policy status
    remains not_verified and must not be used for authentication or authorization.
    """
    if not isinstance(assessment, Assessment):
        raise TypeError("assessment must be an Assessment")
    if isinstance(policy, str):
        policy = get_policy_profile(policy)
    if not isinstance(policy, AssessmentPolicy):
        raise TypeError("policy must be an AssessmentPolicy or profile name")

    verified = assessment.verification_status is VerificationStatus.VERIFIED
    confidence = Confidence.HIGH if verified else Confidence.MEDIUM
    findings = _evaluate_algorithm(assessment, policy, confidence, verified)
    findings.extend(
        _evaluate_required_claims(assessment.claims, policy, confidence, verified)
    )
    now = policy.now_timestamp if policy.now_timestamp is not None else time.time()
    findings.extend(
        _evaluate_time_claims(assessment.claims, policy, now, confidence, verified)
    )
    findings.extend(
        _evaluate_issuer_audience(assessment.claims, policy, confidence, verified)
    )
    non_policy_findings = [item for item in assessment.findings if item.stage != "policy"]
    combined_findings = tuple(non_policy_findings + findings)
    ids = [item.id for item in combined_findings]
    if len(ids) != len(set(ids)):
        raise ValueError(
            "policy evaluation produced a finding ID that conflicts with an existing finding"
        )

    warnings = tuple(
        warning for warning in assessment.warnings if warning != _UNVERIFIED_POLICY_WARNING
    )
    if not verified:
        warnings += (_UNVERIFIED_POLICY_WARNING,)
    status = "not_verified" if not verified else ("failed" if findings else "passed")
    metadata = {
        "profile": policy.name,
        "status": status,
        "compliant": (not findings) if verified else None,
        "observed_compliant": not findings,
        "accepted_algorithms": list(policy.accepted_algorithms),
        "required_claims": list(policy.required_claims),
        "time_claims": list(policy.time_claims),
        "issuer_configured": policy.issuer is not None,
        "audience_configured": policy.audience is not None,
        "issuer_required": policy.require_issuer,
        "audience_required": policy.require_audience,
        "leeway_seconds": policy.leeway_seconds,
        "max_future_iat_seconds": policy.max_future_iat_seconds,
    }
    return replace(
        assessment, findings=combined_findings, warnings=warnings, policy=metadata
    )
