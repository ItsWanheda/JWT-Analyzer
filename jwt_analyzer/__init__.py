"""Stable public API for JWT Analyzer v2.

Inspection decodes untrusted data only. Signature verification and application
claim-policy evaluation are separate stages; neither alone authorizes access.
Internal implementation modules are not part of this import contract.
"""

from .api import inspect_token, verify_signature_with_public_key, verify_with_public_key
from .batch import BatchResult, assess_many, iter_assessments
from .exceptions import (
    BatchLimitError,
    ConfigurationError,
    JWTAnalyzerError,
    TokenAssessmentError,
)
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
    "BatchLimitError",
    "BatchResult",
    "Confidence",
    "ConfigurationError",
    "Finding",
    "JWTAnalyzerError",
    "Severity",
    "TokenAssessmentError",
    "VerificationStatus",
    "__version__",
    "assess_many",
    "baseline_policy",
    "evaluate_policy",
    "get_policy_profile",
    "inspect_token",
    "iter_assessments",
    "strict_policy",
    "verify_signature_with_public_key",
    "verify_with_public_key",
]
