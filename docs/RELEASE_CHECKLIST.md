# JWT Analyzer 2.0.0 Release Checklist

> **Release status — STABLE SOURCE RELEASE: v2.0.0.** Source integration into `main` completed on 2026-11-08 (commit `3ee1bd37d063bb3cd042572693ae98a12fc7e1c9`). The M7 acceptance reviews are complete per maintainer confirmation. Distribution tagging and registry publication are separate operations.

Review the [v2.0.0 release notes](RELEASE_NOTES_2.0.0.md) together with the [v1.2.x migration guide](MIGRATING_TO_V2.md). Operator and maintainer approval is required before publication.

## Release identity

| Item | Expected value |
|---|---|
| Project | JWT Analyzer |
| Release-preparation branch | `feat/m7-release-candidate` |
| Package metadata at source integration | `2.0.0.dev0` (recorded on the integration commit; update only as part of an approved package build) |
| Core CLI/Python API | CPython 3.9–3.14 |
| Optional HTTP service/dashboard | CPython 3.10–3.14 |
| Python package artifacts | Wheel and source distribution |
| Optional components | HTTP service/dashboard and Playwright E2E extra |
| Release authorization | Explicit maintainer approval after all gates and independent review |

The source release is integrated into `main`. Version metadata changes, Git tags, and package/image publication must use the separately authorized distribution workflow and verified release artifacts.

## M7 release gates

- [x] **M7-01 — Migration guide reviewed.** Operator review of legacy command/API/environment/configuration/report/plugin mappings completed (maintainer confirmation, 2026-11-08).
- [x] **M7-02 — Clean-install matrix passes.** Editable, wheel and source installs passed on Linux, Windows and macOS for CPython 3.9–3.14; core and optional-service tests, package build/clean install, Chromium E2E and Docker wordlist check passed in [v2 CI run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094) (33/33 jobs on commit `a2640e98`).
- [x] **M7-03 — Supply-chain artifacts verified.** Dependency audit, CycloneDX SBOM, wheel/sdist hashes, build record, same-run repeat-build, SLSA provenance and SBOM attestations passed, including repository/signer/predicate verification in [M7 supply-chain run #42502255064](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255064) on candidate commit `a2640e98`. All four downloaded SHA-256 manifest entries were checked. Repeatability is same-run/same-toolchain only, not independent or cross-platform.
- [x] **M7-04 — Independent security review completed.** The independent review and findings disposition were confirmed by the project maintainer on 2026-11-08; reviewer identity is not mirrored in this public summary. A checklist prepared by the implementer is not an independent review.
- [x] **M7-05 — Release notes and operator checklist approved.** Supported versions, breaking changes, limitations, upgrade/rollback procedure and publication plan approved (maintainer confirmation, 2026-11-08).

## Continuous integration evidence

The standard v2 workflow must be green for the exact candidate commit:

- [x] Core regression tests on CPython 3.9, 3.10, 3.11, 3.12, 3.13 and 3.14.
- [x] Optional HTTP service security tests on CPython 3.10–3.14; core CLI/API tests cover Python 3.9–3.14.
- [x] Public API lint, formatting, type checks, static security scan, and adversarial regression checks.
- [x] Chromium dashboard E2E and accessibility-oriented regression checks.
- [x] Wheel/sdist build, metadata validation, clean wheel installation and legacy/v2 CLI smoke checks.
- [x] Docker image build and bundled starter-wordlist validation.
- [x] Cross-platform editable, wheel and sdist install smoke checks on Linux, Windows and macOS across the six supported Python versions.
- [x] Supply-chain workflow completes without known vulnerable dependencies or missing attestations.

Recorded release-build evidence: source commit `a2640e98e9c420b4c0ff2ec33b49c9c5c7932904` passed [v2 CI run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094) (33/33 jobs) and [M7 supply-chain run #42502255064](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255064), including provenance and CycloneDX SBOM attestation verification. The artifact from the latter run was downloaded and all four SHA-256 manifest entries were independently checked. A green run on a different commit is not release evidence.

## Artifact verification

The supply-chain workflow produces a wheel, source distribution, CycloneDX dependency SBOM, build record and SHA-256 manifest. It attaches SLSA provenance and CycloneDX SBOM attestations to both package artifacts, then verifies both predicate types against the expected repository and signer workflow before the job passes.

Before distribution, verify each package artifact:

    gh attestation verify dist/<wheel-filename>.whl --repo ItsWanheda/JWT-Analyzer
    gh attestation verify dist/<source-archive-filename>.tar.gz --repo ItsWanheda/JWT-Analyzer
    gh attestation verify dist/<wheel-filename>.whl --repo ItsWanheda/JWT-Analyzer --predicate-type https://cyclonedx.org/bom
    gh attestation verify dist/<source-archive-filename>.tar.gz --repo ItsWanheda/JWT-Analyzer --predicate-type https://cyclonedx.org/bom

Then independently compare the downloaded artifact's SHA-256 digest with dist/SHA256SUMS.txt and the committed workflow run metadata. Do not assume that the SBOM alone proves the package contents; inspect the wheel and sdist file lists as part of the package review.

The current build record compares two builds from the same source commit on the same hosted runner using the same toolchain and SOURCE_DATE_EPOCH. This is a same-run repeatability check, not an independent third-party rebuild or a cross-platform bit-for-bit reproducibility claim.

### Supply-chain evidence and limitations

The M7 workflow audits the pinned third-party dependency set installed from the runtime and optional development/service/E2E extras, emits a CycloneDX JSON SBOM, builds the wheel and sdist twice with one fixed source epoch, compares their SHA-256 digests, and records the exact source commit and tool versions. It attaches GitHub SLSA provenance and SBOM attestations to each package artifact, then uploads the artifact set to the workflow run.

The repeat-build comparison is intentionally scoped to two builds on the same hosted runner with the same source and toolchain. It is not a claim of independent or cross-platform reproducibility. The dependency SBOM describes the audited Python dependency environment, not every operating-system library inside a Docker image. The M7 Docker validation remains a separate workflow gate. No package is published to PyPI and no Docker image is pushed by this workflow.

## Recorded v2.0.0 build evidence

| Evidence | Recorded result |
|---|---|
| Release-preparation branch | `feat/m7-release-candidate` |
| Application source CI | [Run #42502255094](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255094), 33/33 jobs successful on `a2640e98` |
| Supply-chain CI | [Run #42502255064](https://github.com/ItsWanheda/JWT-Analyzer/actions/runs/42502255064), successful with provenance and SBOM verification on `a2640e98` |
| Candidate build artifact | `m7-supply-chain-a2640e98e9c420b4c0ff2ec33b49c9c5c7932904` (workflow artifact ID `13626265515`) |
| Dependency audit | 88 components; 0 components with known advisories; 0 fixes required |
| Repeat-build check | Wheel and sdist digest equality between two builds on the same runner/toolchain and fixed `SOURCE_DATE_EPOCH`; no independent/cross-platform reproducibility claim |

Downloaded artifact hashes (verified against `SHA256SUMS.txt`):

- Wheel: `a691121a7ea12cf6012b4c0cc71691ea3ca3667876e75dddfcc8c66c32494614`
- Source distribution: `9f3069368cdc5869efe9109358c595f3d1301f548e2738dc5645ce9ef636e993`
- CycloneDX SBOM: `4b4fad96f126f50059ef3689df834c1f6bd8c97ae01765245abbac7da6e58364`
- Build record: `2e2dd45760950188c59853a50a5856022929799c884414158227c967f1f66bad`

The candidate build artifact is retained as a GitHub Actions workflow artifact, not as a PyPI or Docker publication. Re-run the documented attestation and digest verification commands against any artifact copied for distribution. These records document M7-02/M7-03 technical validation; review and approval completion is recorded above per maintainer confirmation.

## Independent security review record

**Reviewer:** Independent reviewer (identity not mirrored in this public summary)  
**Review date:** 2026-11-08 (maintainer confirmation)  
**Reviewed commit:** v2.0.0 source integration, `3ee1bd37d063bb3cd042572693ae98a12fc7e1c9`  
**Review scope:** source, tests, parser and cryptographic verification, JWKS destination validation and DNS pinning, SSRF/network boundaries, HMAC resource caps, report schemas and redaction, HTML escaping/CSP, HTTP service authentication and abuse limits, dashboard browser state, plugin discovery/loading/capabilities/trust boundary, package contents and CI workflows.

| Finding ID | Severity | Evidence / affected code | Required action | Status | Verified by |
|---|---|---|---|---|---|
| Independent security review | Findings reviewed and dispositioned (per maintainer confirmation) | v2.0.0 source and security boundaries | No unresolved critical/high blockers reported | Complete | Maintainer confirmation, 2026-11-08 |

Release-blocking rule: no unresolved critical or high severity finding. Medium/low findings must have a documented disposition, owner, and follow-up issue where appropriate. The reviewer must independently confirm fixes; author self-review does not satisfy M7-04.

## Operator upgrade procedure

1. Pin the currently deployed 1.2.x version and preserve the exact wheel/container digest, environment variables, configuration files, and report parsers.
2. Validate the v2.0.0 migration in a staging environment before changing production automation.
3. Read docs/MIGRATING_TO_V2.md and map each legacy command, API, environment variable, report parser and plugin to its v2 replacement or documented non-equivalent behavior.
4. Install the verified v2.0.0 wheel after attestation and digest validation. Install the service extra only when the HTTP service/dashboard is required.
5. Run representative valid, expired, malformed, wrong-key, wrong-algorithm, wrong-issuer and wrong-audience cases. Confirm signature state is distinct from policy state.
6. Compare JSON, HTML and SARIF outputs. Verify redaction defaults, explicit sensitive-export handling, exit codes and downstream CI thresholds.
7. Test the dashboard/service only in a controlled environment. Keep loopback binding unless remote access is deliberately configured with bearer authentication, exact Host allowlisting and TLS termination or a private access-controlled network.
8. Review plugin packages individually. Plugins are trusted in-process code and are not sandboxed; enable only trusted packages.
9. Retain the completed security-review and maintainer-approval records with the deployment change before production rollout.
10. Roll out to a limited environment, monitor errors and report diffs, then expand only after the operator's acceptance criteria pass.

## Rollback procedure

- Keep the exact prior 1.2.x wheel or immutable container digest and the previous deployment configuration available until the v2 rollout is accepted.
- Roll back by redeploying the pinned 1.2.x artifact; do not attempt to make a v2 environment look like v1 by changing only the package version string.
- Restore the saved v1 configuration and CLI invocations. Restore the prior report parsers and automation together with the package.
- Preserve v2-generated reports separately. Do not discard audit evidence or mix v1/v2 JSON contracts in one parser without explicit schema detection.
- Record the rollback commit/artifact, trigger, timestamp, affected environment and follow-up issue.

## Final maintainer authorization

- [x] M0–M6 acceptance evidence reviewed and M6-05 closed (full CI run #42502255094, 33/33 jobs).
- [x] Every M7 gate above is complete (maintainer confirmation, 2026-11-08).
- [x] Migration guide reviewed by an operator (maintainer confirmation, 2026-11-08).
- [x] Independent security review signed off; no unresolved critical/high blockers reported (maintainer confirmation, 2026-11-08).
- [x] Release notes, README, SECURITY.md and supported runtime documentation updated for the v2.0.0 stable source release. Package metadata and registry artifacts remain governed by the separate distribution workflow.
- [ ] Package metadata version bump from `2.0.0.dev0` to `2.0.0` remains a separate distribution-build task.
- [x] Release candidate CI and supply-chain validation completed; exact run evidence is recorded above (maintainer confirmation, 2026-11-08).
- [x] Maintainer authorized the stable source release and documentation status update (2026-11-08). Separate tag and registry publication actions are not included here.

**The stable source release is integrated into `main`. A Git tag, PyPI upload, Docker push, and production deployment must each be performed and verified as separate distribution/operations actions.**
