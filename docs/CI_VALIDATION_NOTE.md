# Temporary CI validation

This file is isolated to the `v2.0.0-ci-validation` branch and exists only to trigger the v2 CI workflow against the current `v2.0.0` base. It is not intended to be merged or included in the 2.0.0 release.

Validation trigger updated after the current public-key verification, strict signature parsing, and lint fixes. Keep this file outside the release branch.

Rerun trigger: current public-key verification now rejects symmetric algorithms and the remaining lint warning was fixed.

Import ordering follow-up trigger after ruff flagged a duplicate-module import block.

Final formatting follow-up: remove extra trailing blank line reported by Ruff format.

Type-check follow-up: pin mypy to version 1.x for the declared Python 3.9 support and annotate the verification error tuple.

Service/dashboard validation trigger after latest Host allowlist, remote-bind, and optional service test changes.

Service compatibility rerun after pinning Starlette below 1.0, and after rate-limiter state-cap regression coverage.

Validation trigger after scoped service lint exceptions and bounded rate-limiter state fixes.

Validation trigger after fixing import grouping and service lint boundary.

Final current-head validation trigger after explicit package imports and test-client Host header fix.

Rerun trigger after service import spacing fix and explicit Host header in service test client.

Validation rerun after applying the Host allowlist to body/rate-limit tests and fixing module docstring spacing.
