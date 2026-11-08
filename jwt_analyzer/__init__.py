"""Stable public API for JWT Analyzer v2.

Inspection decodes untrusted data only. Signature verification and application
claim-policy evaluation are separate stages; neither alone authorizes access.
Internal implementation modules are not part of this import contract.
"""

__version__ = "2.0.0.dev0"

from .api import inspect_token, verify_signature_with_public_key, verify_with_public_key
from .batch import BatchResult, assess_many, iter_assessments
from .exceptions import (
    BatchLimitError,
    ConfigurationError,
    JWTAnalyzerError,
    ReportValidationError,
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
from .plugins import PLUGIN_API_VERSION, PluginManager, PluginManifest, PluginRun
from .policy import (
    AssessmentPolicy,
    baseline_policy,
    evaluate_policy,
    get_policy_profile,
    strict_policy,
)
from .reporting import (
    ReportFormat,
    render_report,
    threshold_exceeded,
    validate_json_report,
    validate_sarif_report,
    write_report,
)

__all__ = [
    "ASSESSMENT_SCHEMA_VERSION",
    "PLUGIN_API_VERSION",
    "Assessment",
    "AssessmentPolicy",
    "BatchLimitError",
    "BatchResult",
    "Confidence",
    "ConfigurationError",
    "Finding",
    "JWTAnalyzerError",
    "PLUGIN_API_VERSION",
    "PluginManager",
    "PluginManifest",
    "PluginRun",
    "ReportFormat",
    "ReportValidationError",
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
    "render_report",
    "strict_policy",
    "threshold_exceeded",
    "validate_json_report",
    "validate_sarif_report",
    "verify_signature_with_public_key",
    "verify_with_public_key",
    "write_report",
]
