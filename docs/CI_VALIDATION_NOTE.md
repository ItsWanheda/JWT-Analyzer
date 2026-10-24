# Temporary CI validation

This file is isolated to the `v2.0.0-ci-validation` branch and exists only to trigger the v2 CI workflow against the current `v2.0.0` base. It is not intended to be merged or included in the 2.0.0 release.

Validation trigger updated after the current public-key verification, strict signature parsing, and lint fixes. Keep this file outside the release branch.

Rerun trigger: current public-key verification now rejects symmetric algorithms and the remaining lint warning was fixed.

Import ordering follow-up trigger after ruff flagged a duplicate-module import block.

Final formatting follow-up: remove extra trailing blank line reported by Ruff format.
