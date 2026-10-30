"""Public Python API for conservative, non-verifying JWT inspection."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from core.parser import parse_jwt
from core.security import check_kid_injection
from core.verification import (
    DEFAULT_ASYMMETRIC_ALGORITHMS,
)
from core.verification import (
    verify_signature_with_public_key as _verify_signature_with_public_key,
)

from .models import Assessment, Confidence, Finding, Severity, VerificationStatus
from .policy import evaluate_policy, get_policy_profile


def inspect_token(token: str) -> Assessment:
    """Inspect a JWT's structure and report token-only indicators.

    This function does *not* validate a signature, issuer, audience, or remote
    verifier behavior. Returned claims are attacker-controlled until a
    separate verification step succeeds. The original token is never stored
    in the returned assessment.

    Args:
        token: Compact serialized JWT string.

    Returns:
        An :class:`Assessment` with decoded header/claims and conservative
        indicators.

    Raises:
        ValueError: If the token is malformed or exceeds parser limits.
    """
    parsed = parse_jwt(token)
    header = parsed["header"]
    claims = parsed["payload"]
    findings: list[Finding] = []
    warnings = [parsed["warning"]]

    algorithm: Any = header.get("alg")
    if isinstance(algorithm, str) and algorithm.lower() == "none":
        findings.append(
            Finding(
                id="jwt.algorithm.none_declared",
                title="Unsigned algorithm declared",
                description=(
                    "The token header declares alg=none. This confirms the header value; "
                    "it does not establish that any server accepts unsigned tokens or is "
                    "vulnerable to a bypass."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="signature-policy",
                recommendation=(
                    "Verify that the target pins an explicit algorithm allowlist and rejects "
                    "unsigned tokens unless an unsigned profile is intentionally required."
                ),
                observation="The token header declares alg=none.",
                impact="A verifier that accepts unsigned tokens could permit token forgery.",
                limitations=(
                    "The header alone does not prove that a target accepts unsigned tokens."
                ),
                evidence={
                    "algorithm": algorithm,
                    "signature_present": parsed["signature_present"],
                },
            )
        )
    elif not isinstance(algorithm, str) or not algorithm:
        findings.append(
            Finding(
                id="jwt.algorithm.missing",
                title="Missing or invalid algorithm header",
                description="The decoded header does not contain a non-empty string alg value.",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="token-structure",
                recommendation=(
                    "Reject malformed JWT headers and configure accepted algorithms explicitly."
                ),
                observation="The header does not contain a valid non-empty algorithm name.",
                impact="Algorithm selection may be ambiguous or fail closed incorrectly.",
                limitations="This observation describes the header, not remote verifier behavior.",
                evidence={"algorithm_type": type(algorithm).__name__},
            )
        )

    if "exp" not in claims:
        findings.append(
            Finding(
                id="jwt.claim.exp_missing",
                title="Expiration claim is missing",
                description=(
                    "The decoded payload has no exp claim. Whether this token is accepted "
                    "and what lifetime policy applies must be checked at the verifier."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="claim-policy",
                recommendation=(
                    "Require a bounded lifetime appropriate to the application's token policy."
                ),
                observation="The decoded payload has no exp claim.",
                impact="A verifier that requires token expiry should reject this token.",
                limitations="The payload is untrusted until signature verification succeeds.",
                evidence={"claim": "exp", "present": False},
            )
        )

    try:
        kid_result = check_kid_injection(token)
    except Exception:  # Defensive boundary: heuristic checks must not break inspection.
        kid_result = {"status": "error"}
        warnings.append("The optional kid heuristic could not complete; no conclusion was drawn.")

    if kid_result.get("status") == "suspicious_input":
        findings.append(
            Finding(
                id="jwt.header.kid_suspicious_indicator",
                title="Suspicious kid header indicator",
                description=(
                    "The kid value matches one or more heuristic patterns. This is an input "
                    "indicator only; it does not prove SQL, path, or command injection."
                ),
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                category="key-selection",
                recommendation=(
                    "Treat kid as an opaque key identifier. Resolve it only against a fixed, "
                    "trusted key set; never interpolate it into SQL, filesystem paths, or commands."
                ),
                observation="The kid value matches one or more suspicious input patterns.",
                impact="Unsafe downstream use of kid may create injection or key-selection risks.",
                limitations="This heuristic does not prove SQL, path, or command injection.",
                evidence={"indicators": kid_result.get("vulnerability_types", [])},
            )
        )

    return Assessment(
        header=header,
        claims=claims,
        signature_present=parsed["signature_present"],
        findings=tuple(findings),
        verification_status=VerificationStatus.NOT_ATTEMPTED,
        warnings=tuple(warnings),
    )


def _validate_verification_options(
    algorithms: Sequence[str],
    key_content: str,
    issuer: str | None,
    audience: str | None,
    leeway: int,
) -> tuple[str, ...]:
    """Validate user-supplied verification constraints before parsing or crypto."""
    if isinstance(algorithms, (str, bytes)) or not isinstance(algorithms, Sequence):
        raise TypeError("algorithms must be a sequence of allowed algorithm names")
    algorithm_list = tuple(algorithms)
    if not algorithm_list or any(
        not isinstance(alg, str) or not alg.strip() for alg in algorithm_list
    ):
        raise ValueError("algorithms must be a non-empty sequence of allowed algorithm names")
    if len(set(algorithm_list)) != len(algorithm_list):
        raise ValueError("algorithms must not contain duplicates")
    unsupported = sorted(set(algorithm_list).difference(DEFAULT_ASYMMETRIC_ALGORITHMS))
    if unsupported:
        raise ValueError(
            "algorithms must be supported asymmetric algorithms; unsupported: "
            + ", ".join(unsupported)
        )
    if not isinstance(key_content, str) or not key_content.strip():
        raise ValueError("key_content must contain a PEM public key or public JWK")
    if issuer is not None and (not isinstance(issuer, str) or not issuer):
        raise ValueError("issuer must be a non-empty string when provided")
    if audience is not None and (not isinstance(audience, str) or not audience):
        raise ValueError("audience must be a non-empty string when provided")
    if isinstance(leeway, bool) or not isinstance(leeway, int) or leeway < 0:
        raise ValueError("leeway must be a non-negative integer number of seconds")
    return algorithm_list


def verify_signature_with_public_key(
    token: str,
    key_content: str,
    *,
    algorithms: Sequence[str],
) -> Assessment:
    """Verify a signature only; apply claim policy separately with evaluate_policy()."""
    algorithm_list = _validate_verification_options(
        algorithms, key_content, issuer=None, audience=None, leeway=0
    )
    parsed = parse_jwt(token)
    raw_result = _verify_signature_with_public_key(
        token, key_content, algorithms=list(algorithm_list)
    )
    raw_status = raw_result.get("status")
    errors: tuple[str, ...] = ()
    if raw_status == "valid" and raw_result.get("verified") is True:
        status = VerificationStatus.VERIFIED
        validated_claims = raw_result.get("payload")
        if not isinstance(validated_claims, dict):
            status = VerificationStatus.ERROR
            claims = parsed["payload"]
            errors = ("Verifier returned an unexpected payload type.",)
        else:
            claims = validated_claims
    elif raw_status == "invalid":
        status = VerificationStatus.INVALID
        claims = parsed["payload"]
        errors = ("JWT signature verification failed.",)
    else:
        status = VerificationStatus.ERROR
        claims = parsed["payload"]
        errors = (str(raw_result.get("error") or "Signature verification could not be completed."),)

    if status is VerificationStatus.VERIFIED:
        warnings = (
            (
                "Cryptographic signature verified; apply application-specific authorization policy "
                "before trusting identity or permissions."
            ),
        )
    else:
        warnings = (parsed["warning"],)

    verification = {
        "status": status.value,
        "algorithms": list(algorithm_list),
        "verified": status is VerificationStatus.VERIFIED,
        "mode": "signature_only",
    }
    return Assessment(
        header=parsed["header"],
        claims=claims,
        signature_present=parsed["signature_present"],
        verification=verification,
        verification_status=status,
        warnings=warnings,
        errors=errors,
    )


def verify_with_public_key(
    token: str,
    key_content: str,
    *,
    algorithms: Sequence[str],
    issuer: str | None = None,
    audience: str | None = None,
    leeway: int = 0,
) -> Assessment:
    """Convenience pipeline: verify the signature, then evaluate baseline policy.

    A valid signature with a wrong issuer remains cryptographically VERIFIED.
    The separate policy result records that the token does not meet that policy.
    """
    algorithm_list = _validate_verification_options(
        algorithms, key_content, issuer, audience, leeway
    )
    assessment = verify_signature_with_public_key(token, key_content, algorithms=algorithm_list)
    verification = dict(assessment.verification or {})
    verification.update(
        {
            "issuer": issuer,
            "audience": audience,
            "leeway_seconds": leeway,
            "mode": "signature_then_policy",
        }
    )
    assessment = replace(assessment, verification=verification)
    policy = get_policy_profile(
        "baseline",
        issuer=issuer,
        audience=audience,
        require_issuer=issuer is not None,
        require_audience=audience is not None,
        leeway_seconds=leeway,
    )
    return evaluate_policy(assessment, policy)

