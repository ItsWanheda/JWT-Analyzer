# Reporting and CI integrations (M4)

JWT Analyzer v2 reports are derived from the public normalized Assessment model and its schema v1.1. The public reporters share finding IDs, severity, confidence, stage, evidence, limitations and remediation; format adapters do not reinterpret findings.

## Formats and schemas

- **JSON** uses report envelope schema v1.0 and embeds the complete normalized Assessment v1.1 object. The assessment is validated against jwt_analyzer/assessment-v1.1.schema.json and the envelope against jwt_analyzer/report-v1.schema.json.
- **HTML** is a self-contained report. Dynamic text and serialized assessment data are HTML-escaped before insertion. It does not execute scripts or fetch remote resources.
- **SARIF** uses SARIF 2.1.0 and is validated against the vendored jwt_analyzer/sarif-2.1.0.schema.json. Each normalized finding becomes one SARIF result and one rule. Severity is mapped consistently: critical/high → error, medium → warning, low/info → note. JWT assessment results do not identify source-code locations, so the exporter does not fabricate file locations.

Validation is offline; no report generation step fetches a schema at runtime.

## CLI

Create an assessment using the v2 inspect command, then render it:

    jwt-analyzer-v2 inspect --token-file token.jwt > assessment.json
    jwt-analyzer-v2 report --assessment-file assessment.json --format sarif --output jwt-analyzer.sarif --fail-on high

--assessment-file accepts either a bare Assessment v1.1 object or the JSON envelope emitted by inspect. Input is strict UTF-8 JSON, duplicate object keys and non-finite numbers are rejected, and the input size is capped at 5 MiB.

Supported formats are json, html, and sarif. Without --output, the report is written to stdout. File output is written atomically using owner-only permissions where the operating system supports them.

## CI threshold policy

The default threshold is high: critical and high findings return exit code 1; medium, low and informational findings do not fail the gate. Select an explicit threshold with --fail-on:

| --fail-on | Exit code 1 when any finding is |
|---|---|
| none | Never |
| info | Informational or higher |
| low | Low or higher |
| medium | Medium or higher |
| high | High or critical |
| critical | Critical |

Exit code 0 means no finding met the selected threshold. Exit code 1 means at least one finding met it; the requested report is still written. Exit code 2 means configuration, input, validation or output failed. The CLI's structured JSON errors are written to stderr.

The default can be set in JSON/YAML configuration with fail_on_severity, or with JWT_ANALYZER_FAIL_ON_SEVERITY; command-line --fail-on takes precedence over configuration.

Example configuration:

    fail_on_severity: high

Example GitHub Actions workflow fragment:

    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4
      - name: Install JWT Analyzer
        run: python -m pip install "jwt-analyzer==2.0.0.dev0"
      - name: Inspect and gate JWT
        run: |
          jwt-analyzer-v2 inspect --token-file token.jwt > assessment.json
          jwt-analyzer-v2 report --assessment-file assessment.json --format sarif --output jwt-analyzer.sarif --fail-on high
      - name: Upload SARIF
        if: always() && hashFiles('jwt-analyzer.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: jwt-analyzer.sarif

Use a version/package source appropriate for your environment; the example above illustrates command wiring and should match the artifact version being validated.

## Redaction and sensitive exports

JSON, HTML and SARIF redact sensitive claim identifiers, likely credentials, JWT-like strings and detected PII by default. The JSON envelope records redaction_applied; SARIF run properties record the same state.

Sensitive values can only be retained by the explicit --include-sensitive CLI option or the corresponding Python API argument include_sensitive=True. This is intended for controlled local workflows. Do not upload unredacted reports to CI artifacts, issue trackers, shared logs or code-scanning services.

The CLI never prints the input compact JWT as part of a report. Report validation failures use sanitized messages and do not echo invalid report contents.

## Python API

    from jwt_analyzer import render_report, threshold_exceeded

    json_text = render_report(assessment, "json")
    html_text = render_report(assessment, "html")
    sarif_text = render_report(assessment, "sarif")

    if threshold_exceeded(assessment, "high"):
        raise SystemExit(1)

For trusted local processing only:

    sensitive_json = render_report(assessment, "json", include_sensitive=True)

write_report(path, content) writes atomically and creates a file with owner-only permissions where supported.
