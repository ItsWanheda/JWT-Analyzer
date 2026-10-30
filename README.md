# 🔐 JWT Analyzer

> A CLI security tool for analyzing, testing, and breaking JSON Web Tokens.
> Built for pentesters, bug bounty hunters, and security teams who need to
> actually understand what's inside a JWT, not just decode it.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0.dev0--unreleased-orange.svg)](CHANGELOG.md)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)

---

> **v2 development status:** `v2.0.0.dev0` is pre-release work on the `v2.0.0` branch. It is not the stable release, and this branch must not be used as a production upgrade until the release gates pass.

## ⚡ Quick Start

```bash
# Option 1: pip (fastest for daily use)
pip install jwt-analyzer
jwt-analyzer audit --token-file token.txt

# Option 2: from the v2 development branch (not a release)
git clone --branch v2.0.0 https://github.com/ItsWanheda/jwt-analyzer.git
cd jwt-analyzer
pip install -e ".[dev]"
python main.py audit --token-file sample_token.txt

# Option 3: Docker (best for CI/CD)
docker compose --profile audit run --rm jwt-analyzer \
    audit --token-file /tokens/jwt.txt
```

The `audit` command is the main one — it runs every check and gives you a report.

---

## 🤔 What does it actually do?

Most JWT tools just decode the base64. This one actually **looks for problems**:

| Check | What it finds |
|-------|---------------|
| `none` algorithm indicator | Flags a header declaring `alg=none`; target acceptance must be verified separately |
| Algorithm/key policy | Flags policy-review indicators; token-only inspection does not prove algorithm confusion |
| Suspicious `kid` values | Flags SQLi / path-traversal / command-pattern indicators; does not prove injection |
| PII / secret scanning | Credit cards, SSNs, AWS keys, passwords leaking through payloads |
| HMAC secret testing | Bounded wordlist testing for HS256/384/512 with worker, candidate, candidate-size and timeout caps |
| JWKS verification | Retrieves eligible public keys over guarded HTTPS and verifies signatures against compatible keys |
| Payload diffing | Shows exactly what changed between two tokens |
| Token forgery | Crafts new tokens with custom payloads (for auth testing) |

---

## 🐍 v2 Python API (development)

The v2 public import surface is `jwt_analyzer`. The API below performs structural inspection only:

```python
from jwt_analyzer import inspect_token

assessment = inspect_token(compact_jwt)
print(assessment.to_dict())
assert assessment.verification_status.value == "not_attempted"
```

Decoded claims are untrusted until signature verification and your application's claim policy both succeed. An `alg=none` or suspicious `kid` value is an indicator, not proof that a target accepts an attack. The assessment does not store the original compact token, but its decoded claims can still contain sensitive data; redact them before logging or sharing reports.

### Explicit public-key verification

Signature verification is a separate call and requires an explicit, non-empty algorithm allowlist:

```python
from pathlib import Path
from jwt_analyzer import verify_with_public_key

assessment = verify_with_public_key(
    compact_jwt,
    Path("public.pem").read_text(encoding="utf-8"),
    algorithms=["RS256"],
    issuer="https://issuer.example",
    audience="jwt-api",
)

if assessment.verification_status.value != "verified":
    raise ValueError(f"JWT signature was not verified: {assessment.errors}")
if assessment.policy is None or assessment.policy["status"] != "passed":
    raise ValueError("JWT did not satisfy the configured claim policy")
```

Use a trusted PEM public key or public JWK obtained from a trusted source. If issuer or audience is omitted, that claim is not validated by this call. A verified signature is not an authorization decision; still enforce application-specific scope, tenant, role and access-control rules. The v2 API keeps `verification_status` (cryptographic signature state) separate from `policy["status"]` (`passed`, `failed`, or `not_verified`).

This API is part of the unreleased `2.0.0.dev0` branch and may change until the v2 release gates pass.

### Policy profiles and normalized results

The shared M1 engine separates parsing, cryptographic verification, claim policy, and presentation. Inspection never changes `verification_status` from `not_attempted`. The signature-only API is explicit:

```python
from pathlib import Path
from jwt_analyzer import evaluate_policy, get_policy_profile, verify_signature_with_public_key

signature_result = verify_signature_with_public_key(
    compact_jwt,
    Path("public.pem").read_text(encoding="utf-8"),
    algorithms=["RS256"],
)
assessment = evaluate_policy(
    signature_result,
    get_policy_profile(
        "strict",
        issuer="https://issuer.example",
        audience="jwt-api",
    ),
)
print(assessment.to_dict())
```

The baseline profile requires an expiry claim; the strict profile additionally requires issuer, audience, issued-at and subject claims and uses a narrower algorithm allowlist. Build an organization-specific policy with `AssessmentPolicy(name="custom", ...)` or use `get_policy_profile("baseline", ...)` with explicit overrides.

`Assessment.to_json()` and `Assessment.from_json()` provide deterministic JSON round-tripping for schema version 1.1. The JSON Schema is included in the package at `jwt_analyzer/assessment-v1.1.schema.json`. Findings have stable IDs, explicit limitations and deterministic severity-then-ID ordering. Decoded claims remain potentially sensitive even though the compact token itself is not stored.

Policy checks over unverified claims are advisory only. A `not_verified` policy result is not a signature result and must never be used as authentication or authorization.

### M2 parser, verification, and resource-safety boundaries

M2 hardens the inputs and expensive operations used by the verifier:

- Compact JWTs are limited to **1 MiB**. Base64URL segments must be canonical, and the decoded header and payload must be JSON objects.
- Security-sensitive JSON rejects duplicate object keys, non-finite numbers, invalid UTF-8, lone UTF-16 surrogates and excessive structures. The parser caps nesting at **64 levels**, values at **100,000 nodes**, and integer values at **128 digits**. Valid surrogate pairs are normalized; keys that collide after normalization are rejected.
- Public-key material is limited to **64 KiB**. Signature verification uses a supported asymmetric algorithm allowlist; do not derive trusted algorithms from an unverified JWT header.
- JWKS retrieval is HTTPS-only by default, preserves TLS certificate/hostname verification, pins validated DNS results to the connection, does not follow redirects, and caps responses at **1 MiB** and **1,000 keys**. It uses one deadline across DNS, connect, TLS and response reads. Expired cached keys are not used as stale fallback.
- HMAC wordlist testing supports HS256/384/512 and streams candidates through a bounded worker pool: at most **32 workers**, **1,000,000 candidates**, and **4 KiB per candidate**; the timeout is capped at **one hour**. Cancellation is cooperative: a cryptographic call already executing cannot be safely force-killed.
- Findings distinguish confirmed local observations from heuristic indicators and unknown server-side behavior. A suspicious `kid` or declared `alg=none` is not proof that a remote verifier accepts an attack.

See [JWKS retrieval security](docs/JWKS_SECURITY.md), [finding semantics](docs/SECURITY_FINDING_SEMANTICS.md), and the [v2 migration guide](docs/MIGRATING_TO_V2.md) for the detailed boundaries and operational caveats.

### Optional HTTP API and dashboard

The HTTP service is an opt-in extra; the CLI and Python package do not require FastAPI or Uvicorn.

```bash
python -m pip install -e ".[service]"
export JWT_ANALYZER_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
jwt-analyzer-api --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/dashboard`. The service defaults to loopback, checks `Host` values, limits request size and assessment request rate, and does not store or log request bodies. The dashboard does not persist tokens in browser storage. Set `JWT_ANALYZER_API_TOKEN` to require bearer authentication on assessment endpoints.

Remote binds require `--allow-remote`, a bearer token at least 32 characters long, and explicit `--allowed-host` values. This service is plain HTTP; use remote mode only behind a TLS-terminating proxy or on a private, access-controlled network. See [HTTP service security and endpoint documentation](docs/HTTP_SERVICE.md). The service is still unreleased v2 functionality and is not intended to authorize users or protect an internet-facing application.


---

## 📦 Installation

### From source (recommended for development)

```bash
git clone https://github.com/ItsWanheda/jwt-analyzer.git
cd jwt-analyzer
pip install -r requirements.txt
```

**Runtime requirements** (`requirements.txt`):
- Python 3.9+
- `pyjwt[crypto] >= 2.8.0` — RS/ES algorithm support
- `cryptography >= 41.0.0` — crypto backend
- `requests >= 2.31.0` — JWKS fetching
- `rich >= 13.0.0` — pretty terminal output
- `click >= 8.1.0` — CLI framework
- `pyyaml >= 6.0` — config file support

**Dev requirements** (`requirements-dev.txt`):
- `pytest >= 7.0`
- `pytest-cov >= 4.0`
- `mypy >= 1.0`
- `ruff >= 0.1.0` (linter)

### Via Docker

```bash
docker pull ItsWanheda/jwt-analyzer:latest
# or build locally:
docker compose build
```

### Via pip (when published to PyPI)

```bash
pip install jwt-analyzer
```

---

## 💻 System Requirements

| Component | Minimum | Tested |
|-----------|---------|--------|
| Python | 3.9 | **3.14.6** |
| RAM | 256 MB | 1 GB (large wordlists) |
| Disk | 50 MB | 200 MB (with bundled wordlists) |
| OS | Any | Windows 10/11 / Ubuntu 22.04 / macOS 14 |

> **Windows users:** Use `py` instead of `python` to launch scripts.
> Token files saved by PowerShell `Set-Content` may carry a UTF-8 BOM —
> the tool strips it automatically (`utf-8-sig` encoding), so this is transparent.

### Python version notes

- **3.9 – 3.13**: Fully supported.
- **3.14**: Fully supported. Note that 3.14's `re` module enforces stricter
  pattern parsing, which surfaced one IPv4 regex bug in v1.2.0 (fixed in v1.2.1).

---

## 🚀 Usage

### Main command: `audit`

Runs every check and produces a report. This is what you want 90% of the time.

```bash
python main.py audit --token-file tokens/jwt.txt
```

**Output:**
```
Audit Summary
  Critical: 2
  High:     1
  Medium:   0
  Low:      0

❌ Critical findings - exiting with code 2
```

**Save reports:**
```bash
# JSON only (machine-readable, good for piping)
python main.py audit --token-file token.txt \
    --output reports/audit-1 --format json

# HTML only (great for sharing with non-tech stakeholders)
python main.py audit --token-file token.txt \
    --output reports/audit-1 --format html

# Both
python main.py audit --token-file token.txt \
    --output reports/audit-1 --format both
```

**Useful flags:**
```bash
# Skip brute force if you've already tested that vector
python main.py audit --token-file token.txt --skip-bruteforce

# Use a bigger wordlist + more workers
python main.py audit --token-file token.txt \
    --wordlist /usr/share/wordlists/jwt-secrets-10k.txt \
    --workers 16

# Enable verbose/debug logging
python main.py --verbose audit --token-file token.txt
```

### Individual commands

Sometimes you want just one thing. These are the building blocks:

#### `analyze` — decode and inspect
```bash
python main.py analyze --token-file token.txt
```
Shows header, payload, and expiry status. **No signature verification.**

#### `security` — vulnerability checks only
```bash
python main.py security --token-file token.txt
```
Checks for `alg=none`, suspicious `kid` patterns, and algorithm/key-policy indicators. These are evidence-based findings; token-only inspection does not prove remote verifier behavior or injection.

#### `brute-force` — crack the signing secret
```bash
python main.py brute-force --token-file token.txt \
    --wordlist utils/wordlists/common_secrets.txt \
    --workers 8
```
Streams candidates through a bounded worker pool. Only tests symmetric
algorithms (HS256/384/512); asymmetric algorithms use keys, not shared secrets.
The implementation caps workers at 32, candidate attempts at 1,000,000,
individual candidates at 4 KiB, and the timeout at 3,600 seconds. A timeout
stops new work and requests cooperative worker shutdown; it cannot interrupt
a cryptographic call already executing.

#### `diff` — compare two tokens
```bash
python main.py diff --token1 old.txt --token2 new.txt
```
Perfect for "I had `role: user` and now I want `role: admin`, what changed?"

#### `verify-rsa` — verify with a public key
```bash
# PEM format
python main.py verify-rsa --token-file token.txt --public-key public.pem

# JWK format (auto-detected)
python main.py verify-rsa --token-file token.txt --public-key key.jwk
```

#### `verify-jwks` — verify against a live JWKS endpoint
```bash
python main.py verify-jwks --token-file token.txt \
    --jwks-url https://auth.example.com/.well-known/jwks.json

# TLS verification is always enabled; use a valid certificate and trust store.
# Redirects are not followed; destination and response limits are enforced.
```

#### `forge` — create a custom token
```bash
python main.py forge \
    --token-file original.txt \
    --payload-file new-payload.json \
    --secret mysecret \
    --algorithm HS256 \
    --output forged.txt \
    --yes
```
⚠️ See [Security & Ethics](#-security--ethics) before using this.
The `--yes` flag exists because we want you to think twice.

---

## 📂 Project Structure

```
jwt-analyzer/
├── jwt_analyzer/                 # Public v2 Python API and normalized assessment models
│   ├── api.py                     # Conservative token inspection API
│   └── models.py                  # Assessment and finding schema
├── main.py                       # CLI entry point
├── config.py                     # Configuration & env vars
├── Dockerfile                    # Production container
├── Dockerfile.dev                # Dev container with live reload
├── docker-compose.yml            # Multi-profile orchestration
├── Makefile                      # Convenience commands
├── requirements.txt              # Runtime dependencies
├── requirements-dev.txt          # Test/dev dependencies
├── .env.example                  # Documented env vars
│
├── core/
│   ├── parser.py                 # Bounded JWT parsing & claim extraction
│   ├── strict_json.py             # Duplicate-safe, resource-bounded JSON decoding
│   ├── security.py               # Vuln checks (none alg, kid injection, etc.)
│   ├── verification.py           # RSA/ECDSA public key verification
│   ├── forgery.py                # Token crafting
│   ├── diff.py                   # Payload comparison
│   ├── jwks.py                   # JWKS endpoint fetching + caching
│   ├── sensitive_scanner.py      # PII / secret detection
│   ├── async_security.py         # Parallel brute force
│   └── logging_config.py         # JSON + console logging
│
├── utils/
│   ├── io.py                     # File reading helpers
│   ├── report.py                 # HTML report generation
│   └── wordlists/
│       └── common_secrets.txt    # Small starter list; add an authorized wordlist for deeper checks
│
├── plugins/                      # Custom check plugins (optional)
│   └── README.md                 # How to write plugins
│
├── scripts/
│   └── batch_audit.sh            # Process a directory of tokens
│
├── sample_token.txt              # Try it immediately
├── LICENSE
├── README.md                     # You are here
├── CHANGELOG.md
├── CONTRIBUTING.md
└── SECURITY.md
```

---

## 📚 Bundled wordlist policy

The wheel and Docker image contain only a six-entry starter list at
`utils/wordlists/common_secrets.txt`. It is not a comprehensive password corpus.
No larger corpus is downloaded or bundled automatically. An operator-supplied
list must be explicitly opted into with `--wordlist /path/to/authorized-list.txt`
or `JWT_ANALYZER_WORDLIST_PATH`. Treat custom wordlists as sensitive files.
See [the wordlist policy](docs/WORDLIST_POLICY.md).

## ⚙️ Configuration

### Environment variables

All have sensible defaults. Override when needed:

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_ANALYZER_WORDLIST_PATH` | `utils/wordlists/common_secrets.txt` | Path to secrets wordlist |
| `JWT_ANALYZER_TIMEOUT` | `300` | Brute force timeout (seconds) |
| `JWT_ANALYZER_WORKERS` | `8` | Parallel workers for brute force |
| `JWT_ANALYZER_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `JWT_ANALYZER_ENABLE_RICH` | `true` | Pretty terminal output |

Example:
```bash
JWT_ANALYZER_LOG_LEVEL=DEBUG \
JWT_ANALYZER_WORKERS=16 \
python main.py audit --token-file token.txt
```

Or use the `.env.example` template:
```bash
cp .env.example .env
# edit .env
set -a && source .env && set +a
python main.py audit --token-file token.txt
```

### Config file (optional)

Drop a `jwt-analyzer.yaml` in your working directory to override defaults
without env vars:

```yaml
wordlist_path: /opt/secrets/jwt-megalist.txt
brute_force_timeout: 600
parallel_workers: 16
log_level: DEBUG
```

---

## 🐳 Docker Usage

### Available profiles

The `docker-compose.yml` uses profiles so nothing auto-starts. Pick the one
that matches your workflow:

| Profile | Use case |
|---------|----------|
| `audit` | One-off analysis of a single token |
| `ci` | Automated scans in CI/CD pipelines (respects exit codes) |
| `dev` | Live development with source mounted as volume |
| `batch` | Process a directory of tokens overnight |
| `jwks` | Fetch and inspect JWKS endpoint contents |

### Quick examples

**Audit a single token:**
```bash
docker compose --profile audit run --rm jwt-analyzer \
    audit --token-file /tokens/jwt.txt \
          --output /reports/audit-1
```

**Verify against a live JWKS:**
```bash
docker compose --profile jwks run --rm jwt-analyzer \
    verify-jwks --token-file /tokens/jwt.txt \
                --jwks-url https://auth.example.com/.well-known/jwks.json
```

**Batch process a directory:**
```bash
# Drop JWTs (one per .txt file) into ./tokens/batch/, then:
docker compose --profile batch up
ls reports/batch/
```

### CI/CD integration

Exit codes for pipeline gating:
- `0` = clean (only LOW/MEDIUM findings, or none)
- `1` = HIGH severity findings
- `2` = CRITICAL findings

**GitHub Actions example:**
```yaml
- name: JWT Security Audit
  run: |
    docker compose --profile ci run --rm \
      -v ${{ github.workspace }}/tokens:/app/tokens:ro \
      jwt-analyzer audit \
        --token-file /app/tokens/prod-jwt.txt \
        --skip-bruteforce
```

**GitLab CI example:**
```yaml
jwt-audit:
  stage: security
  script:
    - docker compose --profile ci run --rm
        -v "$CI_PROJECT_DIR/tokens:/app/tokens:ro"
        jwt-analyzer audit
          --token-file /app/tokens/jwt.txt
          --skip-bruteforce
  allow_failure: false
```

### Development mode

Live-reload your source code changes without rebuilding the image:

```bash
docker compose --profile dev run --rm -it jwt-analyzer bash
# Now you're inside the container:
python main.py audit --token-file /tokens/jwt.txt
```

---

## 🔍 Example Workflow

A realistic pentest scenario:

```bash
# 1. Found a JWT in the app's localStorage. Dump it.
python main.py analyze --token-file captured.txt

# 2. Quick security check - 'none' alg? weak kid? confused algorithms?
python main.py security --token-file captured.txt

# 3. Try to crack the signing secret
python main.py brute-force --token-file captured.txt \
    --wordlist utils/wordlists/common_secrets.txt

# 4. Got the secret. Compare a normal user token vs admin token
python main.py diff --token1 user-token.txt --token2 admin-token.txt
# → role changed from "user" to "admin", exp extended

# 5. Forge a new admin token
cat > admin-payload.json << EOF
{
  "sub": "1234567890",
  "role": "admin",
  "exp": 9999999999
}
EOF

python main.py forge \
    --token-file captured.txt \
    --payload-file admin-payload.json \
    --secret cracked-secret \
    --output forged-admin.txt \
    --yes

# 6. Full audit with report for the writeup
python main.py audit --token-file captured.txt \
    --output reports/final-audit \
    --format both
```

---

## 🧩 Plugins

Custom checks can be added without modifying core code. Drop a file in
`plugins/` that exposes a `register()` function:

```python
# plugins/my_checks_plugin.py
class MyOrgClaimsPlugin:
    name = "myorg_claims"
    description = "Validates organization-specific JWT claims"

    def check(self, token: str) -> dict:
        # your custom check logic
        ...

def register():
    return MyOrgClaimsPlugin()
```

Plugins auto-load on startup. See `plugins/README.md` for the full API.

---

## 🔧 Troubleshooting

### `'utf-8' codec can't decode byte 0xb1`

Your token file was saved with a non-UTF-8 encoding (usually a UTF-8 BOM from
Windows PowerShell). Re-save it:

```powershell
Get-Content sample_token.txt -Encoding UTF8 | Set-Content sample_token.txt -Encoding UTF8 -NoNewline
```

The tool also auto-handles BOM in v1.2.1+, so this is usually a one-time fix.

### `No such command 'brute_force'`

Click maps function names to hyphenated command names. Use the hyphenated form:

```bash
python main.py brute-force --token-file token.txt   # ✅
python main.py brute_force --token-file token.txt   # ❌
```

### `python: command not found` (Windows)

Use `py` instead:

```powershell
py main.py audit --token-file token.txt
```

### `re.PatternError: nothing to repeat`

You're on Python 3.14 with an older build. Upgrade to v1.2.1 or later —
this was fixed in the IPv4 pattern.

### Forge produces a 3-segment token but it won't verify

Check that `--secret` matches the original token's signing secret.
Run `analyze` on both the original and forged tokens and compare headers —
they should be identical except for `alg`.

---

## 🛡️ Security & Ethics

**Read this. Seriously.**

This tool can forge tokens, crack secrets, and bypass authentication. That's
the point, but it also means you can hurt people with it.

### ✅ Do
- Only test systems you have **written authorization** to test
- Use it for security audits, bug bounties, CTFs, your own apps, and education
- Document what you found and how (that's what `--output reports/` is for)
- Follow responsible disclosure for any vulns you discover

### ❌ Don't
- Don't run this against systems you don't own or have explicit permission for
- Don't use it to access accounts that aren't yours
- Don't be the reason computer fraud laws exist

Unauthorized access to computer systems is illegal in most jurisdictions
(CFAA in the US, Computer Misuse Act in the UK, similar laws everywhere).
The `--yes` flag on `forge` exists because we want you to think twice.

### Reporting vulnerabilities in THIS tool

Found a security bug in jwt-analyzer itself? Please email
**wanheda.work@gmail.com** (do **not** open a public GitHub issue).
See [SECURITY.md](SECURITY.md) for our full disclosure policy.

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Quick checklist for PRs:
- [ ] New functionality is documented in the README
- [ ] Entry added to CHANGELOG.md under `[Unreleased]`
- [ ] No new hardcoded paths or secrets
- [ ] Code passes `ruff check` and `mypy` if you ran them locally
- [ ] Plugin additions follow the pattern in `plugins/README.md`

---

## 📝 License

MIT — see [LICENSE](LICENSE) for the full text.

In short: do what you want, just don't blame us if something goes wrong,
and keep the copyright notice.

---

## 🙏 Credits

- The OWASP JWT cheat sheet — for the vulnerability patterns
- [SecLists](https://github.com/danielmiessler/SecLists) — bundled wordlists
- The PyJWT maintainers — solid crypto library
- Everyone who's reported bugs and contributed fixes

---

## 📚 Further reading

- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWKS retrieval security model](docs/JWKS_SECURITY.md)
- [Security finding semantics](docs/SECURITY_FINDING_SEMANTICS.md)
- [v2 migration guide](docs/MIGRATING_TO_V2.md)
- [PortSwigger Web Security Academy — JWT attacks](https://portswigger.net/web-security/jwt)
- [Auth0 JWT documentation](https://auth0.com/docs/secure/tokens/json-web-tokens)
