"""Stable exception types exposed by the jwt_analyzer public API."""


class JWTAnalyzerError(Exception):
    """Base class for documented public API failures."""


class TokenAssessmentError(JWTAnalyzerError, ValueError):
    """Raised when a token cannot be structurally inspected."""


class ConfigurationError(JWTAnalyzerError, ValueError):
    """Raised when configuration input is invalid or unsafe."""


class BatchLimitError(JWTAnalyzerError, ValueError):
    """Raised when a batch exceeds its configured item limit."""
