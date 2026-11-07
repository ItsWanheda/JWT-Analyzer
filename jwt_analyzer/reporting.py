"""Versioned JSON, HTML, and SARIF reporting for JWT Analyzer assessments."""

from __future__ import annotations

import hashlib
import html
import json
import os
import tempfile
from enum import Enum
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker

from . import __version__
from .exceptions import ReportValidationError
from .models import ASSESSMENT_SCHEMA_VERSION, Assessment
from utils.report import redact_sensitive_data

_REPORT_SCHEMA_VERSION = "1.0"
_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SECURITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "2.5",
    "info": "0.1",
}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ReportFormat(str, Enum):
    """Supported versioned report formats."""

    JSON = "json"
    HTML = "html"
    SARIF = "sarif"


@lru_cache(maxsize=3)
def _load_schema(name: str) -> dict[str, Any]:
    if name not in {
        "assessment-v1.1.schema.json",
        "report-v1.schema.json",
        "sarif-2.1.0.schema.json",
    }:
        raise ValueError("unsupported report schema")
    with files("jwt_analyzer").joinpath(name).open("r", encoding="utf-8") as stream:
        schema = json.load(stream)
    if not isinstance(schema, dict):
        raise ReportValidationError("report schema resource is invalid")
    return schema


def _validate_assessment_data(data: dict[str, Any]) -> None:
    try:
        schema = _load_schema("assessment-v1.1.schema.json")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(data)
    except Exception as exc:
        raise ReportValidationError("assessment does not conform to schema v1.1") from exc


def validate_json_report(report: dict[str, Any]) -> None:
    """Validate the report envelope and its nested normalized assessment."""
    try:
        schema = _load_schema("report-v1.schema.json")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
        assessment = report["assessment"]
        if not isinstance(assessment, dict):
            raise ValueError("assessment must be an object")
        _validate_assessment_data(assessment)
    except ReportValidationError:
        raise
    except Exception as exc:
        raise ReportValidationError("JSON report does not conform to report schema v1.0") from exc


def validate_sarif_report(report: dict[str, Any]) -> None:
    """Validate SARIF output against the vendored SARIF 2.1.0 JSON Schema."""
    try:
        schema = _load_schema("sarif-2.1.0.schema.json")
        Draft7Validator.check_schema(schema)
        Draft7Validator(schema).validate(report)
    except Exception as exc:
        raise ReportValidationError("SARIF output does not conform to SARIF 2.1.0") from exc


def _prepared_assessment(
    assessment: Assessment, *, include_sensitive: bool
) -> dict[str, Any]:
    if not isinstance(assessment, Assessment):
        raise TypeError("assessment must be an Assessment instance")
    raw = assessment.to_dict()
    _validate_assessment_data(raw)
    exported = raw if include_sensitive else redact_sensitive_data(raw)
    _validate_assessment_data(exported)
    return exported


def render_json_report(
    assessment: Assessment, *, include_sensitive: bool = False
) -> str:
    """Render the normalized assessment in the versioned, schema-validated JSON envelope."""
    exported = _prepared_assessment(assessment, include_sensitive=include_sensitive)
    report = {
        "report_schema_version": _REPORT_SCHEMA_VERSION,
        "tool": {"name": "JWT Analyzer", "version": __version__},
        "redaction_applied": not include_sensitive,
        "assessment": exported,
    }
    validate_json_report(report)
    return json.dumps(report, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)


def render_html_report(
    assessment: Assessment, *, include_sensitive: bool = False
) -> str:
    """Render a self-contained HTML report; every dynamic value is HTML-escaped."""
    data = _prepared_assessment(assessment, include_sensitive=include_sensitive)
    findings = data["findings"]
    counts = {
        level: sum(1 for finding in findings if finding["severity"] == level)
        for level in ("critical", "high", "medium", "low", "info")
    }
    cards = "".join(
        f'<li><strong>{level.title()}:</strong> {counts[level]}</li>'
        for level in ("critical", "high", "medium", "low", "info")
    )
    rows = []
    for finding in findings:
        title = html.escape(str(finding["title"]))
        description = html.escape(str(finding["description"]))
        recommendation = html.escape(str(finding.get("recommendation", "")))
        severity = html.escape(str(finding["severity"]).upper())
        rows.append(
            "<tr>"
            f"<td>{severity}</td><td>{title}</td><td>{description}</td>"
            f"<td>{recommendation}</td></tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="4">No findings were reported.</td></tr>')
    assessment_json = html.escape(
        json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2)
    )
    redaction_label = "Applied" if not include_sensitive else "Disabled by explicit opt-in"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="JWT Analyzer {html.escape(__version__)}">
<title>JWT Analyzer assessment report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#20242a}}
table{{border-collapse:collapse;width:100%;margin:1.5rem 0}}
th,td{{border:1px solid #d0d7de;padding:.65rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#f6f8fa}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f8fa;padding:1rem}}
</style>
</head>
<body>
<h1>JWT Analyzer assessment report</h1>
<p><strong>Assessment timestamp (UTC):</strong> {html.escape(data["assessed_at"])}</p>
<p><strong>Assessment schema:</strong> {html.escape(ASSESSMENT_SCHEMA_VERSION)}</p>
<p><strong>Verification status:</strong> {html.escape(data["verification_status"])}</p>
<p><strong>Sensitive-data redaction:</strong> {html.escape(redaction_label)}</p>
<h2>Severity summary</h2><ul>{cards}</ul>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Description</th><th>Recommendation</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
<h2>Normalized assessment data</h2><pre>{assessment_json}</pre>
<p>Decoded JWT claims are untrusted unless signature verification and application policy checks succeeded.</p>
</body></html>"""


def _sarif_document(
    assessment_data: dict[str, Any], *, redaction_applied: bool
) -> dict[str, Any]:
    findings = assessment_data["findings"]
    rules = []
    results = []
    for index, finding in enumerate(findings):
        severity = finding["severity"]
        rule_id = finding["id"]
        rule = {
            "id": rule_id,
            "shortDescription": {"text": finding["title"]},
            "fullDescription": {"text": finding["description"]},
            "defaultConfiguration": {"level": _SEVERITY_LEVEL[severity]},
            "properties": {
                "tags": ["security"],
                "security-severity": _SECURITY_SCORE[severity],
                "confidence": finding["confidence"],
                "stage": finding["stage"],
            },
        }
        if finding.get("recommendation"):
            rule["help"] = {"text": finding["recommendation"]}
        rules.append(rule)
        result = {
            "ruleId": rule_id,
            "ruleIndex": index,
            "level": _SEVERITY_LEVEL[severity],
            "kind": "fail",
            "message": {"text": f'{finding["title"]}: {finding["observation"]}'},
            "partialFingerprints": {
                "jwtAnalyzer/v1": hashlib.sha256(rule_id.encode("utf-8")).hexdigest()
            },
            "properties": {
                "confidence": finding["confidence"],
                "stage": finding["stage"],
                "impact": finding["impact"],
                "limitations": finding["limitations"],
                "recommendation": finding.get("recommendation", ""),
                "evidence": finding["evidence"],
            },
        }
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "JWT Analyzer",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/ItsWanheda/JWT-Analyzer",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "jwt-analyzer/v2/report"},
                "invocations": [{"executionSuccessful": True}],
                "results": results,
                "properties": {
                    "assessmentSchemaVersion": ASSESSMENT_SCHEMA_VERSION,
                    "assessmentTimestamp": assessment_data["assessed_at"],
                    "verificationStatus": assessment_data["verification_status"],
                    "redactionApplied": redaction_applied,
                },
            }
        ],
    }


def render_sarif_report(
    assessment: Assessment, *, include_sensitive: bool = False
) -> str:
    """Render SARIF 2.1.0 with stable rule IDs and matching finding severities."""
    data = _prepared_assessment(assessment, include_sensitive=include_sensitive)
    report = _sarif_document(data, redaction_applied=not include_sensitive)
    validate_sarif_report(report)
    return json.dumps(report, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)


def render_report(
    assessment: Assessment,
    report_format: str | ReportFormat = ReportFormat.JSON,
    *,
    include_sensitive: bool = False,
) -> str:
    """Render one normalized assessment in JSON, HTML, or SARIF."""
    try:
        selected = ReportFormat(report_format)
    except ValueError as exc:
        raise ValueError("report format must be json, html, or sarif") from exc
    renderers = {
        ReportFormat.JSON: render_json_report,
        ReportFormat.HTML: render_html_report,
        ReportFormat.SARIF: render_sarif_report,
    }
    return renderers[selected](assessment, include_sensitive=include_sensitive)


def threshold_exceeded(assessment: Assessment, fail_on: str = "high") -> bool:
    """Return whether any finding meets or exceeds the configured CI severity."""
    if fail_on not in {"none", *_SEVERITY_RANK}:
        raise ValueError("fail_on must be none, info, low, medium, high, or critical")
    if fail_on == "none":
        return False
    threshold = _SEVERITY_RANK[fail_on]
    return any(
        _SEVERITY_RANK[finding.severity.value] >= threshold
        for finding in assessment.findings
    )


def write_report(output_path: str | os.PathLike[str], content: str) -> Path:
    """Atomically write a report with owner-only permissions where supported."""
    target = Path(output_path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return target
