"""Heuristic JWT checks report observations, not proof of server-side vulnerabilities."""
import logging
import time
from typing import Optional

import jwt
from config import Config

logger = logging.getLogger(__name__)


def check_none_algorithm(token: str) -> bool:
    """Return whether the unverified header declares alg=none."""
    try:
        alg = jwt.get_unverified_header(token).get("alg", "")
        return isinstance(alg, str) and alg.lower() == "none"
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        logger.debug("Could not inspect JWT header: %s", exc)
        return False


def check_algorithm_confusion(token: str) -> dict:
    """Describe the declared algorithm without claiming exploitability."""
    try:
        alg = jwt.get_unverified_header(token).get("alg", "")
        symmetric = alg in Config.SUPPORTED_SYMMETRIC_ALGORITHMS
        asymmetric = alg in Config.SUPPORTED_ASYMMETRIC_ALGORITHMS
        return {
            "algorithm": alg, "is_symmetric": symmetric, "is_asymmetric": asymmetric,
            "vulnerable_to_confusion": False,
            "status": "observed" if symmetric or asymmetric else "needs_review",
            "finding": (
                "Asymmetric algorithm observed; token-only inspection cannot establish "
                "algorithm-confusion vulnerability. Verify algorithm pinning and key type."
                if asymmetric else
                "Symmetric algorithm observed; confirm it is explicitly allowed by policy."
                if symmetric else "Missing or unsupported algorithm; review verifier policy."
            ),
            "evidence": {"header_alg": alg},
            "limitations": ["Token-header inspection does not prove server acceptance or exploitability."],
        }
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        return {"status": "error", "error": "Unable to parse JWT header", "details": str(exc)}


def check_kid_injection(token: str) -> dict:
    """Flag suspicious kid values as indicators, not confirmed injection."""
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid", "")
        if not isinstance(kid, str):
            return {"kid_present": "kid" in header, "kid_value": None, "vulnerable": False,
                    "status": "needs_review", "vulnerability_types": [],
                    "finding": "kid is not a string; verifier-specific behavior needs review."}
        lowered = kid.lower()
        indicators = []
        if any(marker in lowered for marker in ("'", '"', " or ", " and ", " union ", " select ", "--", ";")):
            indicators.append("SQL_INJECTION_INDICATOR")
        if ".." in kid or "%2e%2e" in lowered:
            indicators.append("PATH_TRAVERSAL_INDICATOR")
        if any(char in kid for char in (chr(96), "$", "|", "&", "\n", "\r")):
            indicators.append("COMMAND_INJECTION_INDICATOR")
        return {
            "kid_present": bool(kid), "kid_value": kid[:100], "vulnerable": False,
            "status": "suspicious_input" if indicators else "no_known_indicator",
            "vulnerability_types": indicators,
            "finding": ("Suspicious kid value detected; inspect how the target selects keys."
                        if indicators else
                        "No known suspicious pattern detected; this does not establish safety."),
            "limitations": ["Heuristic pattern matching can produce false positives and false negatives."],
        }
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        return {"status": "error", "error": "Unable to parse JWT header", "details": str(exc)}


def brute_force_secret(token: str, wordlist: list,
                       algorithms: Optional[list] = None,
                       timeout: int = 300) -> Optional[str]:
    """Try candidate HMAC secrets for authorized testing only."""
    if algorithms is None:
        algorithms = Config.SUPPORTED_SYMMETRIC_ALGORITHMS
    allowed = set(Config.SUPPORTED_SYMMETRIC_ALGORITHMS)
    algorithms = [alg for alg in algorithms if alg in allowed]
    if timeout <= 0:
        return None
    deadline = time.monotonic() + timeout
    attempts = 0
    for secret in wordlist:
        if time.monotonic() >= deadline:
            logger.warning("Brute force timed out after %d attempts", attempts)
            return None
        for alg in algorithms:
            if time.monotonic() >= deadline:
                logger.warning("Brute force timed out after %d attempts", attempts)
                return None
            attempts += 1
            try:
                jwt.decode(token, secret, algorithms=[alg])
                logger.info("Matching secret found after %d attempts using %s", attempts, alg)
                return secret
            except jwt.InvalidTokenError:
                continue
    return None
