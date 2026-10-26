"""JWT Analyzer v2 public Python API.

Inspection decodes untrusted data only. Signature verification and application
claim-policy evaluation are separate stages; neither alone authorizes access.
"""

from .api import inspect_token, verify_signature_with_public_key, verify_with_public_key
from .models import (
    ASSESSMENT_SCHEMA_VERSION,
    Assessment,
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
)
from .policy import (
    AssessmentPolicy,
    baseline_policy,
    evaluate_policy,
    get_policy_profile,
    strict_policy,
)

__version__ = "2.0.0.dev0"

__all__ = [
    "ASSESSMENT_SCHEMA_VERSION",
    "Assessment",
    "AssessmentPolicy",
    "Confidence",
    "Finding",
    "Severity",
    "VerificationStatus",
    "__version__",
    "baseline_policy",
    "evaluate_policy",
    "get_policy_profile",
    "inspect_token",
    "strict_policy",
    "verify_signature_with_public_key",
    "verify_with_public_key",
]
