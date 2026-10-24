"""JWT Analyzer v2 public Python API.

Inspection decodes untrusted data only. Call a verification operation and
apply an application-specific claim policy before trusting token claims.
"""

from .api import inspect_token
from .models import Assessment, Confidence, Finding, Severity, VerificationStatus

__version__ = "2.0.0.dev0"

__all__ = [
    "Assessment",
    "Confidence",
    "Finding",
    "Severity",
    "VerificationStatus",
    "__version__",
    "inspect_token",
]
