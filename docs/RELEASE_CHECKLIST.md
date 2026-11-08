# JWT Analyzer 2.0.0 Release Checklist

> **Status: candidate preparation only.** The repository remains on 2.0.0.dev0. This checklist does not authorize a release, tag, PyPI upload, Docker push, or production cutover.

Read the [2.0.0 release-notes draft](RELEASE_NOTES_2.0.0.md) together with the [v1.2.x migration guide](MIGRATING_TO_V2.md). The notes remain a draft until reviewed and approved.

## Release identity

| Item | Expected value |
|---|---|
| Project | JWT Analyzer |
| Candidate branch | v2.0.0 after reviewed M7 integration |
| Current development version | 2.0.0.dev0 |
| Core CLI/Python API | CPython 3.9–3.14 |
| Optional HTTP service/dashboard | CPython 3.10–3.14 |
| Python package artifacts | Wheel and source distribution |
| Optional components | HTTP service/dashboard and Playwright E2E extra |
| Release authorization | Explicit maintainer approval after all gates and independent review |

Do not change package metadata to 2.0.0, create a tag, or publish artifacts until the maintainer explicitly authorizes the release commit.

## M7 release gates

- [ ] **M7-01 — Migration guide reviewed.** Confirm every legacy command, API, environment variable, config key, output schema, plugin behavior and optional service change against the exact release commit. Review docs/MIGRATING_TO_V2.md with an operator who owns a v1.2.x integration.
- [ ] **M7-02 — Clean-install matrix passes.** Verify editable, wheel and source installs on Linux, Windows and macOS for CPython 3.9–3.14. Run the CLI/API smoke workflow, Docker build and Docker wordlist check. Preserve run links and logs.
- [ ] **M7-03 — Supply-chain artifacts verified.** Require a clean dependency audit, CycloneDX SBOM, wheel and sdist SHA-256 digests, a build record, SLSA provenance attestations, and SBOM attestations. Verify the attestations against the repository before distributing an artifact.
- [ ] **M7-04 — Independent security review completed.** A reviewer other than the implementation author inspects the source and tests, records evidence, and confirms every critical/high finding is fixed or explicitly blocks the release. A checklist prepared by the implementer is not an independent review.
- [ ] **M7-05 — Release notes and operator checklist approved.** Finalize breaking changes, supported versions, known limitations, installation, configuration migration, backup, rollback and post-upgrade verification steps.

## Continuous integration evidence

The standard v2 workflow must be green for the exact candidate commit:

- [ ] Core regression tests on CPython 3.9, 3.10, 3.11, 3.12, 3.13 and 3.14.
- [ ] Optional HTTP service security tests on CPython 3.10–3.14; core CLI/API tests cover Python 3.9–3.14.
- [ ] Public API lint, formatting, type checks, static security scan, and adversarial regression checks.
- [ ] Chromium dashboard E2E and accessibility-oriented regression checks.
- [ ] Wheel/sdist build, metadata validation, clean wheel installation and legacy/v2 CLI smoke checks.
- [ ] Docker image build and bundled starter-wordlist validation.
- [ ] Cross-platform editable, wheel and sdist install smoke checks on Linux, Windows and macOS across the six supported Python versions.
- [ ] Supply-chain workflow completes without known vulnerable dependencies or missing attestations.

Record the exact commit SHA, workflow run URLs, runner OS labels, Python patch versions, artifact hashes and any skipped jobs. A green run on a different commit is not release evidence.

## Artifact verification

The supply-chain workflow produces a wheel, source distribution, CycloneDX dependency SBOM, build record and SHA-256 manifest. It also attaches provenance and SBOM attestations to both package artifacts.

Before distribution, verify each package artifact:

    gh attestation verify dist/<wheel-filename>.whl --repo ItsWanheda/JWT-Analyzer
    gh attestation verify dist/<source-archive-filename>.tar.gz --repo ItsWanheda/JWT-Analyzer

Then independently compare the downloaded artifact's SHA-256 digest with dist/SHA256SUMS.txt and the committed workflow run metadata. Do not assume that the SBOM alone proves the package contents; inspect the wheel and sdist file lists as part of the package review.

The current build record compares two builds from the same source commit on the same hosted runner using the same toolchain and SOURCE_DATE_EPOCH. This is a same-run repeatability check, not an independent third-party rebuild or a cross-platform bit-for-bit reproducibility claim.

### Supply-chain evidence and limitations

The M7 workflow audits the pinned third-party dependency set installed from the runtime and optional development/service/E2E extras, emits a CycloneDX JSON SBOM, builds the wheel and sdist twice with one fixed source epoch, compares their SHA-256 digests, and records the exact source commit and tool versions. It attaches GitHub SLSA provenance and SBOM attestations to each package artifact, then uploads the artifact set to the workflow run.

The repeat-build comparison is intentionally scoped to two builds on the same hosted runner with the same source and toolchain. It is not a claim of independent or cross-platform reproducibility. The dependency SBOM describes the audited Python dependency environment, not every operating-system library inside a Docker image. The M7 Docker validation remains a separate workflow gate. No package is published to PyPI and no Docker image is pushed by this workflow.

## Independent security review record

**Reviewer:** To be assigned by the maintainer  
**Review date:** Pending  
**Reviewed commit:** Pending  
**Review scope:** source, tests, parser and cryptographic verification, JWKS destination validation and DNS pinning, SSRF/network boundaries, HMAC resource caps, report schemas and redaction, HTML escaping/CSP, HTTP service authentication and abuse limits, dashboard browser state, plugin discovery/loading/capabilities/trust boundary, package contents and CI workflows.

| Finding ID | Severity | Evidence / affected code | Required action | Status | Verified by |
|---|---|---|---|---|---|
| Pending independent review | — | — | Complete review and add findings here | Open | — |

Release-blocking rule: no unresolved critical or high severity finding. Medium/low findings must have a documented disposition, owner, and follow-up issue where appropriate. The reviewer must independently confirm fixes; author self-review does not satisfy M7-04.

## Operator upgrade procedure

1. Pin the currently deployed 1.2.x version and preserve the exact wheel/container digest, environment variables, configuration files, and report parsers.
2. Create a separate environment for the v2 candidate. Do not upgrade the production environment as the first test.
3. Read docs/MIGRATING_TO_V2.md and map each legacy command, API, environment variable, report parser and plugin to its v2 replacement or documented non-equivalent behavior.
4. Install the candidate wheel from a verified local artifact after attestation and digest validation. Install the service extra only when the HTTP service/dashboard is required.
5. Run representative valid, expired, malformed, wrong-key, wrong-algorithm, wrong-issuer and wrong-audience cases. Confirm signature state is distinct from policy state.
6. Compare JSON, HTML and SARIF outputs. Verify redaction defaults, explicit sensitive-export handling, exit codes and downstream CI thresholds.
7. Test the dashboard/service only in a controlled environment. Keep loopback binding unless remote access is deliberately configured with bearer authentication, exact Host allowlisting and TLS termination or a private access-controlled network.
8. Review plugin packages individually. Plugins are trusted in-process code and are not sandboxed; enable only trusted packages.
9. Obtain the independent security review and maintainer sign-off before production rollout.
10. Roll out to a limited environment, monitor errors and report diffs, then expand only after the operator's acceptance criteria pass.

## Rollback procedure

- Keep the exact prior 1.2.x wheel or immutable container digest and the previous deployment configuration available until the v2 rollout is accepted.
- Roll back by redeploying the pinned 1.2.x artifact; do not attempt to make a v2 environment look like v1 by changing only the package version string.
- Restore the saved v1 configuration and CLI invocations. Restore the prior report parsers and automation together with the package.
- Preserve v2-generated reports separately. Do not discard audit evidence or mix v1/v2 JSON contracts in one parser without explicit schema detection.
- Record the rollback commit/artifact, trigger, timestamp, affected environment and follow-up issue.

## Final maintainer authorization

- [ ] M0–M6 acceptance evidence reviewed and M6-05 closed.
- [ ] Every M7 gate above is complete with evidence.
- [ ] Migration guide reviewed by an operator.
- [ ] Independent security review signed off and no critical/high blockers remain.
- [ ] Release notes, package metadata, README, SECURITY.md, Docker metadata and supported Python classifiers agree.
- [ ] Final version bump from 2.0.0.dev0 to 2.0.0 is reviewed on the release commit.
- [ ] Final release commit CI is green.
- [ ] Maintainer explicitly authorizes the tag and the chosen distribution channels.

**No tag, PyPI publish, Docker push or production upgrade is implied by checking or implementing any item in this document.**
