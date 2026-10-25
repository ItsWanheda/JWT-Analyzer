"""Safe HTML report generation for JWT analysis."""
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JWT Security Analysis Report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #f5f5f5; color: #222; }}
.container {{ max-width: 1100px; margin: auto; background: white; padding: 2rem; border-radius: 8px; }}
h1 {{ border-bottom: 3px solid #3498db; padding-bottom: .5rem; }}
.metadata, .summary-card {{ background: #ecf0f1; padding: 1rem; border-radius: 6px; }}
.summary-card {{ display: inline-block; margin: .4rem; min-width: 90px; text-align: center; }}
.number {{ font-size: 1.8rem; font-weight: bold; }}
pre {{ background: #202b36; color: white; padding: 1rem; overflow-wrap: anywhere; white-space: pre-wrap; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ padding: .7rem; text-align: left; border-bottom: 1px solid #ddd; overflow-wrap: anywhere; }}
th {{ background: #34495e; color: white; }}
.critical {{ background: #b42318; color: white; }} .high {{ background: #c65d0a; color: white; }}
.medium {{ background: #946200; color: white; }} .low {{ background: #175cd3; color: white; }}
.ok {{ background: #067647; color: white; padding: .5rem; }}
</style></head><body><main class="container">
<h1>JWT Security Analysis Report</h1>
<div class="metadata"><strong>Generated (UTC):</strong> {timestamp}<br>
<strong>Tool:</strong> JWT Analyzer<br><strong>Analyst:</strong> {analyst}</div>
<section aria-label="Severity summary">
<div class="summary-card"><div class="number">{critical_count}</div>Critical</div>
<div class="summary-card"><div class="number">{high_count}</div>High</div>
<div class="summary-card"><div class="number">{medium_count}</div>Medium</div>
<div class="summary-card"><div class="number">{low_count}</div>Low</div></section>
<h2>Token Information</h2><pre>{token_info}</pre>
<h2>Security Findings</h2>{findings_html}
<h2>Recommendations</h2>{recommendations_html}
<h2>Payload Analysis (redacted)</h2><pre>{payload_json}</pre>
<p>Decoded JWT claims are untrusted unless signature and claim validation succeeded.</p>
</main></body></html>"""

_SENSITIVE_MARKERS = (
    "token", "secret", "password", "passwd", "authorization", "cookie",
    "private_key", "privatekey", "api_key", "apikey", "credential", "email",
    "phone", "address", "ssn", "date_of_birth", "dob", "sub", "name",
    "username", "preferred_username", "given_name", "family_name", "first_name",
    "last_name", "user_id", "employee_id", "birthdate", "birth_date", "location",
)
_FORCE_REDACT_KEYS = {"matched_text", "secret_value", "private_material", "raw_token"}
_COMPACT_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|password|passwd|pwd|secret|token|jwt|id[_-]?token|"
    r"access[_-]?token|refresh[_-]?token|client[_-]?secret|session[_-]?id|api[_-]?key)\b\s*[:=]\s*)"
    r"(?:Bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_URL_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|id_token|access_token|refresh_token|api[_-]?key|client_secret|password|secret|session_id)=)[^&#\s]+"
)
_PII_PATTERNS = (
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"),
    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
)


def _redact_string(value: str) -> str:
    value = _SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", value)
    value = _URL_SECRET_RE.sub(r"\1[REDACTED]", value)
    value = _COMPACT_JWT_RE.sub("[REDACTED: JWT-like value]", value)
    if any(pattern.search(value) for pattern in _PII_PATTERNS):
        return "[REDACTED: potential PII or credential]"
    return value


def _redact(value: Any, key: str = "") -> Any:
    lowered_key = key.lower()
    if lowered_key in _FORCE_REDACT_KEYS or any(
        marker in lowered_key for marker in _SENSITIVE_MARKERS
    ):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def redact_sensitive_data(value: Any) -> Any:
    """Return a recursively redacted copy of a report or log payload."""
    return _redact(value)


def _json_text(value: Any) -> str:
    return json.dumps(_redact(value), indent=2, ensure_ascii=False, default=str)


def generate_html_report(analysis_data: Dict, output_path: str,
                         analyst: str = "Security Team") -> str:
    """Generate an HTML report with escaped values and default redaction."""
    findings = analysis_data.get("findings", [])
    count = lambda level: sum(1 for f in findings if str(f.get("severity", "")).upper() == level)
    html_content = HTML_TEMPLATE.format(
        timestamp=datetime.now(timezone.utc).isoformat(),
        analyst=html.escape(_redact_string(str(analyst))),
        critical_count=count("CRITICAL"), high_count=count("HIGH"),
        medium_count=count("MEDIUM"), low_count=count("LOW"),
        token_info=html.escape(_json_text(_redact(analysis_data.get("token_info", {})))),
        findings_html=_render_findings(_redact(findings)),
        recommendations_html=_generate_recommendations(_redact(findings)),
        payload_json=html.escape(_json_text(_redact(analysis_data.get("payload", {})))),
    )
    Path(output_path).write_text(html_content, encoding="utf-8")
    return output_path


def _render_findings(findings: list) -> str:
    if not findings:
        return '<p class="ok">No findings were reported by the configured checks.</p>'
    rows = []
    allowed = {"critical", "high", "medium", "low"}
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        css_class = severity.lower() if severity.lower() in allowed else ""
        rows.append(
            "<tr>"
            f'<td><span class="{css_class}">{html.escape(severity)}</span></td>'
            f"<td>{html.escape(str(finding.get('title', '')))}</td>"
            f"<td>{html.escape(str(finding.get('description', '')))}</td>"
            f"<td>{html.escape(str(finding.get('remediation', '')))}</td>"
            "</tr>"
        )
    return ("<table><thead><tr><th>Severity</th><th>Finding</th><th>Description</th>"
            "<th>Remediation</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _generate_recommendations(findings: list) -> str:
    types = {str(f.get("type", "")) for f in findings}
    recs = []
    if "none_algorithm" in types:
        recs.append("Reject unsigned tokens and enforce an explicit algorithm allowlist.")
    if "weak_secret" in types:
        recs.append("Use a strong random signing secret and rotate it.")
    if "no_expiry" in types:
        recs.append("Set and validate expiration according to application policy.")
    if "sensitive_data" in types:
        recs.append("Avoid sensitive personal data in signed-but-unencrypted JWT payloads.")
    if not recs:
        recs.append("Review all observations and limitations; absence of findings does not prove security.")
    return "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in recs) + "</ul>"
