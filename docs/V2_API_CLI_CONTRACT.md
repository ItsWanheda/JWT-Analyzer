# JWT Analyzer v2 API and CLI Contract

> **Status:** development contract for 2.0.0.dev0. It is not a stable release guarantee until M3 acceptance and the release gates pass.

## Public Python API

The supported import surface is jwt_analyzer. Import documented functions, models, policies, batch helpers and exception types from this namespace. Modules under core, utils, and the repository root are implementation details and are not covered by API compatibility guarantees.

- inspect_token(token) performs structural inspection only. Its verification status is always not_attempted.
- verify_signature_with_public_key(token, key_content, algorithms=...) performs signature verification only. An explicit asymmetric algorithm allowlist is mandatory.
- evaluate_policy(assessment, policy) evaluates claim policy separately. A policy result on unverified claims is advisory.
- verify_with_public_key(...) is the convenience signature-then-baseline-policy pipeline.
- iter_assessments(tokens, max_items=...) and assess_many(...) stream individual outcomes. Failed items do not stop subsequent items.
- Assessment.to_dict() and Assessment.to_json() use the versioned assessment schema. Consumers should check schema_version and stable finding IDs.

Public exceptions derive from JWTAnalyzerError. Invalid token input raises TokenAssessmentError (also a ValueError). Invalid configuration raises ConfigurationError. A hard batch item cap raises BatchLimitError.

## Versioned CLI

Install the project and invoke jwt-analyzer-v2. The existing jwt-analyzer entry point and legacy commands remain available during the v2 transition; they are not silently redirected to the new contract.

### Inspect one token

    jwt-analyzer-v2 inspect --token-file token.jwt --evaluate-policy

Stdout contains exactly one compact JSON document with schema_version (CLI envelope version 1), status=ok, and assessment (normalized Assessment schema v1.1).

### Stream a batch

The input is UTF-8, one compact JWT per non-empty line:

    jwt-analyzer-v2 batch --input-file tokens.txt

The command emits one JSON line per input item, then one final summary line. Add --evaluate-policy to apply the configured claim policy; inspection remains unverified, so these policy results are advisory. It does not collect the whole batch in memory. Blank lines are ignored. Per-item results have status=succeeded or status=failed; the summary has status=complete or status=partial.

### Exit codes and streams

| Exit code | Meaning |
|---:|---|
| 0 | All requested items completed successfully |
| 1 | Token assessment failed (single-token failure or partial batch) |
| 2 | CLI usage, input-file, configuration, or batch-limit error |

Successful result documents go to stdout. Structured errors go to stderr as JSON with schema_version, status=error, and an error object containing a stable code and a non-sensitive message. Do not parse human-readable legacy CLI output as this contract.

## Configuration

Configuration is optional. JSON and YAML files are supported, with a 1 MiB file-size limit and safe YAML parsing. Unknown keys are rejected.

Precedence: built-in defaults < configuration file < environment variables.

Supported file keys:

    policy: baseline
    policy_options:
      issuer: https://issuer.example
      audience: orders-api
      require_issuer: true
      require_audience: true
    max_batch_items: 10000
    wordlist_path: ./wordlists/custom.txt

Supported environment overrides:
- JWT_ANALYZER_POLICY
- JWT_ANALYZER_MAX_BATCH_ITEMS
- JWT_ANALYZER_WORDLIST_PATH

The default maximum batch size is 10,000 non-empty input items. Set a deliberate lower cap for constrained environments. The CLI inspection and batch commands do not imply signature verification or authorization.

## Compatibility and migration

- The jwt_analyzer namespace and schema v1.1 are the supported v2 integration surface.
- Internal core.*, utils.*, config.Config, and direct main.py imports are legacy implementation details.
- The existing jwt-analyzer command remains available during the 2.0.0 development transition. New automation should adopt jwt-analyzer-v2 and its JSON contract.
- Legacy command output is not guaranteed to match the versioned CLI envelope. Migrate parsers to the JSON contract before removing legacy invocation.
- Do not restore insecure TLS-disable flags or infer successful verification from decoded token claims.
- No legacy alias may bypass explicit algorithm allowlists, policy evaluation, input limits, or output redaction.

The legacy entry point will not be removed before a separately documented deprecation period and a major/minor compatibility decision. This development branch does not publish a package or remove existing commands.
