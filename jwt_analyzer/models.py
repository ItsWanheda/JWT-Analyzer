"""Versioned, JSON-safe result models for the JWT Analyzer v2 assessment engine."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

ASSESSMENT_SCHEMA_VERSION = "1.1"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_FINDING_STAGES = frozenset({"inspection", "verification", "policy"})


class Severity(str, Enum):
    """Normalized finding severity, independent of any presentation format."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence in the stated observation, not in unobserved server behavior."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationStatus(str, Enum):
    """Cryptographic signature-verification state."""

    NOT_ATTEMPTED = "not_attempted"
    VERIFIED = "verified"
    INVALID = "invalid"
    ERROR = "error"


def _utc_timestamp() -> str:
    """Return an explicit UTC timestamp in the stable ISO-8601 form."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_value(value: Any) -> Any:
    """Normalize supported values and reject objects that JSON cannot represent."""
    if isinstance(value, Enum):
        return value.value
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("assessment values must not contain non-finite numbers")
        return value
    if isinstance(value, datetime):
        normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return normalized.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        normalized_mapping: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("assessment object keys must be strings")
            normalized_mapping[key] = _json_value(item)
        return normalized_mapping
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    raise TypeError(f"unsupported assessment value type: {type(value).__name__}")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _require_text(name: str, value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        requirement = "string" if allow_empty else "non-empty string"
        raise ValueError(f"{name} must be a {requirement}")
    return value


@dataclass(frozen=True)
class Finding:
    """A stable finding with observation, impact, evidence, limits, and remediation."""

    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    category: str = "general"
    recommendation: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)
    observation: str = ""
    impact: str = "Review the impact in the target application's security context."
    limitations: str = (
        "This finding is limited to the evidence described and does not by itself "
        "establish remote exploitability."
    )
    stage: str = "inspection"

    def __post_init__(self) -> None:
        for field_name in ("id", "title", "description", "category"):
            _require_text(field_name, getattr(self, field_name))
        _require_text("recommendation", self.recommendation, allow_empty=True)
        observation = self.observation or self.description
        _require_text("observation", observation)
        _require_text("impact", self.impact)
        _require_text("limitations", self.limitations)
        if self.stage not in _FINDING_STAGES:
            raise ValueError("stage must be inspection, verification, or policy")
        try:
            object.__setattr__(self, "severity", Severity(self.severity))
            object.__setattr__(self, "confidence", Confidence(self.confidence))
        except (TypeError, ValueError) as exc:
            raise ValueError("severity or confidence is not a supported value") from exc
        if not isinstance(self.evidence, Mapping):
            raise TypeError("evidence must be a mapping")
        normalized_evidence = _json_value(deepcopy(self.evidence))
        object.__setattr__(self, "evidence", normalized_evidence)
        object.__setattr__(self, "observation", observation)

    def to_dict(self) -> dict[str, Any]:
        """Return the documented JSON representation with stable field names."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "recommendation": self.recommendation,
            "observation": self.observation,
            "impact": self.impact,
            "limitations": self.limitations,
            "stage": self.stage,
            "evidence": _json_value(self.evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Finding:
        """Validate and deserialize one finding from the v1.1 contract."""
        if not isinstance(value, Mapping):
            raise TypeError("finding data must be a mapping")
        allowed = {
            "id",
            "title",
            "description",
            "severity",
            "confidence",
            "category",
            "recommendation",
            "observation",
            "impact",
            "limitations",
            "stage",
            "evidence",
        }
        unknown = set(value).difference(allowed)
        if unknown:
            raise ValueError("unknown finding field(s): " + ", ".join(sorted(unknown)))
        required = {"id", "title", "description", "severity"}
        missing = required.difference(value)
        if missing:
            raise ValueError("missing finding field(s): " + ", ".join(sorted(missing)))
        return cls(
            id=value["id"],
            title=value["title"],
            description=value["description"],
            severity=value["severity"],
            confidence=value.get("confidence", Confidence.MEDIUM),
            category=value.get("category", "general"),
            recommendation=value.get("recommendation", ""),
            evidence=value.get("evidence", {}),
            observation=value.get("observation", ""),
            impact=value.get(
                "impact", "Review the impact in the target application's security context."
            ),
            limitations=value.get(
                "limitations",
                "This finding is limited to the evidence described and does not by itself "
                "establish remote exploitability.",
            ),
            stage=value.get("stage", "inspection"),
        )


def _normalize_timestamp(value: str) -> str:
    _require_text("assessed_at", value)
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("assessed_at must be a valid ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError("assessed_at must include a timezone")
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_findings(values: Any) -> tuple[Finding, ...]:
    findings = tuple(values)
    if any(not isinstance(item, Finding) for item in findings):
        raise TypeError("findings must contain Finding objects")
    ids = [item.id for item in findings]
    if len(ids) != len(set(ids)):
        raise ValueError("finding IDs must be unique within an assessment")
    return tuple(sorted(findings, key=lambda item: (_SEVERITY_ORDER[item.severity.value], item.id)))


def _normalize_text_sequence(name: str, values: Any) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, (tuple, list)):
        raise TypeError(f"{name} must be a sequence of strings")
    normalized = tuple(values)
    if any(not isinstance(item, str) or not item.strip() for item in normalized):
        raise ValueError(f"{name} must contain non-empty strings")
    return normalized

@dataclass(frozen=True)
class Assessment:
    """A versioned assessment; no field stores the original compact JWT string."""

    header: Mapping[str, Any]
    claims: Mapping[str, Any]
    signature_present: bool
    verification: Mapping[str, Any] | None = None
    findings: tuple[Finding, ...] = ()
    verification_status: VerificationStatus = VerificationStatus.NOT_ATTEMPTED
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    schema_version: str = ASSESSMENT_SCHEMA_VERSION
    assessed_at: str = field(default_factory=_utc_timestamp)
    policy: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.header, Mapping) or not isinstance(self.claims, Mapping):
            raise TypeError("header and claims must be mappings")
        if not isinstance(self.signature_present, bool):
            raise TypeError("signature_present must be a boolean")
        if self.schema_version != ASSESSMENT_SCHEMA_VERSION:
            raise ValueError(f"unsupported assessment schema version: {self.schema_version!r}")
        object.__setattr__(self, "assessed_at", _normalize_timestamp(self.assessed_at))
        for name in ("verification", "policy"):
            value = getattr(self, name)
            if value is not None:
                if not isinstance(value, Mapping):
                    raise TypeError(f"{name} must be a mapping or None")
                object.__setattr__(self, name, _json_value(deepcopy(value)))
        object.__setattr__(self, "header", _json_value(deepcopy(self.header)))
        object.__setattr__(self, "claims", _json_value(deepcopy(self.claims)))
        try:
            status = VerificationStatus(self.verification_status)
        except (TypeError, ValueError) as exc:
            raise ValueError("verification_status is not a supported value") from exc
        object.__setattr__(self, "verification_status", status)
        object.__setattr__(self, "findings", _normalize_findings(self.findings))
        for name in ("warnings", "errors"):
            object.__setattr__(self, name, _normalize_text_sequence(name, getattr(self, name)))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain JSON-compatible structure; the token is never included."""
        result = {
            "schema_version": self.schema_version,
            "assessed_at": self.assessed_at,
            "verification_status": self.verification_status.value,
            "signature_present": self.signature_present,
            "verification": (
                _json_value(self.verification) if self.verification is not None else None
            ),
            "policy": _json_value(self.policy) if self.policy is not None else None,
            "header": _json_value(self.header),
            "claims": _json_value(self.claims),
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }
        _json_value(result)
        return result

    def to_json(self, *, indent: int | None = None) -> str:
        """Return deterministic JSON: sorted object keys and no non-standard numbers."""
        kwargs: dict[str, Any] = {
            "sort_keys": True,
            "ensure_ascii": False,
            "allow_nan": False,
        }
        if indent is None:
            kwargs["separators"] = (",", ":")
        else:
            kwargs["indent"] = indent
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Assessment:
        """Validate and deserialize an assessment produced by the v1.1 schema."""
        if not isinstance(value, Mapping):
            raise TypeError("assessment data must be a mapping")
        allowed = {
            "schema_version",
            "assessed_at",
            "verification_status",
            "signature_present",
            "verification",
            "policy",
            "header",
            "claims",
            "findings",
            "warnings",
            "errors",
        }
        unknown = set(value).difference(allowed)
        if unknown:
            raise ValueError("unknown assessment field(s): " + ", ".join(sorted(unknown)))
        missing = allowed.difference(value)
        if missing:
            raise ValueError("missing assessment field(s): " + ", ".join(sorted(missing)))
        if value["schema_version"] != ASSESSMENT_SCHEMA_VERSION:
            raise ValueError(f"unsupported assessment schema version: {value['schema_version']!r}")
        findings = value["findings"]
        if not isinstance(findings, list):
            raise TypeError("findings must be a list")
        return cls(
            header=value["header"],
            claims=value["claims"],
            signature_present=value["signature_present"],
            verification=value["verification"],
            findings=tuple(Finding.from_dict(item) for item in findings),
            verification_status=value["verification_status"],
            warnings=value["warnings"],
            errors=value["errors"],
            schema_version=value["schema_version"],
            assessed_at=value["assessed_at"],
            policy=value["policy"],
        )

    @classmethod
    def from_json(cls, value: str) -> Assessment:
        """Deserialize strict JSON and validate the complete public result contract."""
        if not isinstance(value, str):
            raise TypeError("JSON assessment must be a string")
        try:
            parsed = json.loads(
                value,
                parse_constant=_reject_json_constant,
                object_pairs_hook=_unique_object,
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("assessment JSON is malformed") from exc
        if not isinstance(parsed, Mapping):
            raise TypeError("assessment JSON must contain an object")
        return cls.from_dict(parsed)
