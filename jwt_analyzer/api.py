"""Public Python API for conservative, non-verifying JWT inspection."""
from __future__ import annotations

from typing import Any

from core.parser import parse_jwt
from core.security import check_kid_injection

from .models import Assessment, Confidence, Finding, Severity, VerificationStatus


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
                    "The token header declares alg=none. This confirms the header value, "
                    "not that any server accepts unsigned tokens or is vulnerable to a bypass."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="signature-policy",
                recommendation=(
                    "Verify that the target pins an explicit algorithm allowlist and rejects "
                    "unsigned tokens unless an unsigned profile is intentionally required."
                ),
                evidence={"algorithm": algorithm, "signature_present": parsed["signature_present"]},
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
                recommendation="Reject malformed JWT headers and configure accepted algorithms explicitly.",
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
                recommendation="Require a bounded lifetime appropriate to the application's token policy.",
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
                evidence={"indicators": kid_result.get("vulnerability_types", [])},
            )
        )

    return Assessment(
        header=header,
        claims=claims,
        findings=tuple(findings),
        verification_status=VerificationStatus.NOT_ATTEMPTED,
        warnings=tuple(warnings),
    )
