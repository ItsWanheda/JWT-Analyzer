"""Safe HTML report generation for JWT analysis."""
import html
import json
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

_SENSITIVE_MARKERS = ("token", "secret", "password", "passwd", "authorization",
                      "cookie", "private_key", "privatekey", "api_key", "apikey", "credential")


def _redact(value: Any, key: str = "") -> Any:
    if any(marker in key.lower() for marker in _SENSITIVE_MARKERS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    if isinstance(value, str) and value.count(".") == 2 and len(value) > 40:
        return "[REDACTED: JWT-like value]"
    return value


def _json_text(value: Any) -> str:
    return json.dumps(_redact(value), indent=2, ensure_ascii=False, default=str)


def generate_html_report(analysis_data: Dict, output_path: str,
                         analyst: str = "Security Team") -> str:
    """Generate an HTML report with escaped values and default redaction."""
    findings = analysis_data.get("findings", [])
    count = lambda level: sum(1 for f in findings if str(f.get("severity", "")).upper() == level)
    html_content = HTML_TEMPLATE.format(
        timestamp=datetime.now(timezone.utc).isoformat(),
        analyst=html.escape(str(analyst)),
        critical_count=count("CRITICAL"), high_count=count("HIGH"),
        medium_count=count("MEDIUM"), low_count=count("LOW"),
        token_info=html.escape(_json_text(analysis_data.get("token_info", {}))),
        findings_html=_render_findings(findings),
        recommendations_html=_generate_recommendations(findings),
        payload_json=html.escape(_json_text(analysis_data.get("payload", {}))),
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
