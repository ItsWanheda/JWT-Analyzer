"""Stable, JSON-friendly result models for the JWT Analyzer v2 API.

The models deliberately distinguish observed token properties from verified
security conclusions. A finding's confidence describes confidence in the
observation itself, not proof that a remote verifier is vulnerable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class Severity(str, Enum):
    """Normalized finding severity, independent of presentation format."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence in an observed indicator, not in remote exploitability."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationStatus(str, Enum):
    """Signature verification state; inspection alone is never verification."""

    NOT_ATTEMPTED = "not_attempted"
    VERIFIED = "verified"
    INVALID = "invalid"
    ERROR = "error"


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_value(value: Any) -> Any:
    """Convert nested model values to plain JSON-compatible containers."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, datetime):
        normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return normalized.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


@dataclass(frozen=True)
class Finding:
    """A portable finding with explicit severity, confidence, evidence and advice."""

    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    category: str = "general"
    recommendation: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("id", "title", "description", "category"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        try:
            object.__setattr__(self, "severity", Severity(self.severity))
            object.__setattr__(self, "confidence", Confidence(self.confidence))
        except ValueError as exc:
            raise ValueError("severity or confidence is not a supported value") from exc
        if not isinstance(self.evidence, Mapping):
            raise TypeError("evidence must be a mapping")
        object.__setattr__(self, "evidence", dict(self.evidence))

    def to_dict(self) -> dict[str, Any]:
        """Return a stable plain-dictionary representation."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "recommendation": self.recommendation,
            "evidence": _json_value(self.evidence),
        }


@dataclass(frozen=True)
class Assessment:
    """Result of inspecting a JWT; decoded claims remain untrusted input."""

    header: Mapping[str, Any]
    claims: Mapping[str, Any]
    signature_present: bool
    findings: tuple[Finding, ...] = ()
    verification_status: VerificationStatus = VerificationStatus.NOT_ATTEMPTED
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    schema_version: str = "1.0"
    assessed_at: str = field(default_factory=_utc_timestamp)

    def __post_init__(self) -> None:
        if not isinstance(self.header, Mapping) or not isinstance(self.claims, Mapping):
            raise TypeError("header and claims must be mappings")
        if not isinstance(self.signature_present, bool):
            raise TypeError("signature_present must be a boolean")
        object.__setattr__(self, "header", dict(self.header))
        object.__setattr__(self, "claims", dict(self.claims))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "errors", tuple(self.errors))
        try:
            object.__setattr__(
                self,
                "verification_status",
                VerificationStatus(self.verification_status),
            )
        except ValueError as exc:
            raise ValueError("verification_status is not a supported value") from exc
        if not self.schema_version:
            raise ValueError("schema_version must be non-empty")
        if not self.assessed_at:
            raise ValueError("assessed_at must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        """Serialize without ever retaining or returning the original token."""
        return {
            "schema_version": self.schema_version,
            "assessed_at": self.assessed_at,
            "verification_status": self.verification_status.value,
            "signature_present": self.signature_present,
            "header": _json_value(self.header),
            "claims": _json_value(self.claims),
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }
