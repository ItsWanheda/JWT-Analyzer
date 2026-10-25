# Security Policy

> **Security is not a feature, it's a foundation.** 🛡️

---

## 🔒 Supported Versions

We maintain strict version control to ensure security patches are delivered effectively.

| Version | Supported | Status |
| :--- | :---: | :--- |
| **1.2.1** | ✅ | Latest stable line; security fixes should target this line |
| **2.0.0.dev0** | ❌ | Development prerelease; not supported for production use |
| **1.2.0 and older** | ❌ | Upgrade to the latest stable 1.2.x release |
---

## Default report and log handling

The v2 JSON/HTML exports and application logging paths use best-effort default
redaction for JWT-like strings, common credential patterns, sensitive claim fields,
and several common PII patterns. Redaction is a safety net, not a guarantee that
every custom identifier, secret format, or jurisdiction-specific personal datum
will be recognized. Review reports before sharing them and avoid putting full
assessments containing sensitive claims into shared artifacts.

Commands that explicitly display decoded data—including \`analyze\`,
\`verify-rsa\` payload output, payload comparison, and token forging—can display
sensitive values by design. Use these local inspection workflows only in a
controlled environment.

## Optional v2 HTTP Service

The HTTP service and dashboard in `2.0.0.dev0` are experimental and unsupported for production use until the v2 security gates are complete.

- The service binds to loopback by default. Non-loopback binds require explicit opt-in, a bearer token of at least 32 characters, and an exact Host allowlist.
- Use remote mode only behind a TLS-terminating proxy or on a private, access-controlled network. The service itself speaks HTTP and must not receive bearer tokens over untrusted networks in clear text.
- Assessment routes enforce request-size and per-client rate limits. The service does not persist request bodies or log submitted tokens, but response claims can contain sensitive data.
- The service exposes no arbitrary JWKS URL-fetch endpoint. Do not add one without a separate SSRF threat model, destination controls, and adversarial tests.
- A successful JWT signature check is not application authorization. Consumers must enforce issuer/audience requirements and application-specific access policy.
- Report service vulnerabilities privately using the disclosure procedure below; do not test against systems you do not own or have permission to assess.

## 🚨 Reporting a Vulnerability

We prioritize the security of our infrastructure and users above all else. If you believe you have discovered a vulnerability, we request that you **disclose it responsibly** by following our private disclosure process.

### ⚠️ Guidelines
- **DO NOT** open a public issue, pull request, or discussion regarding a potential vulnerability.
- **DO NOT** exploit the vulnerability on live systems.
- **DO NOT** share details of the exploit with third parties until a patch is released.

### 📧 Disclosure Process
Please report all findings directly via email:

**[wanheda.work@gmail.com](mailto:wanheda.work@gmail.com)**

*To ensure we handle your report efficiently, please include:*
* **Proof of Concept (PoC)** or detailed reproduction steps
* **Impact Analysis**
* **Suggested Remediation** (optional)

---

## ⏱️ Response SLA

We treat security reports as high-priority incidents. You can expect the following response timeline:

1.  **Acknowledgment**: Within **48 hours** of initial receipt.
2.  **Analysis & Feedback**: Within **72 hours**, we will provide an initial assessment and our plan for remediation.

---
*Thank you for helping keep this project secure for everyone.*
---
