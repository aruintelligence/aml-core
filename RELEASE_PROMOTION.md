# ĀML Release Promotion Contract

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

ĀML maintains separate **stable** and **preview** release channels. Promotion is an atomic contract change, not a collection of unrelated version edits.

## Current release truth

The machine-readable authority is `project-contract.json`.

At the time this contract was introduced:

- stable: `v1.3.0`
- preview: `v1.4.0-rc.2`
- default channel: stable

These values are descriptive of repository state, not a promise that the preview will become the next stable release without further review.

## Promotion invariant

A release promotion MUST update all affected release surfaces in one reviewed change. At minimum, review:

1. `project-contract.json`
2. `package.json`
3. `CITATION.cff`
4. `README.md`
5. `CHANGELOG.md`
6. `conformance/manifest.json`
7. release notes and migration material, when applicable
8. package/CLI/API compatibility evidence
9. claims ledger changes introduced by the release
10. tags/releases only after the repository state is internally coherent

The project and release coherence CI gates MUST pass before a promotion is considered internally consistent.

## Stable means stable

A preview or release candidate MUST NOT become the default package/CLI/capability contract merely because code exists on `main` or because a prerelease tag exists.

Stable promotion requires an explicit change to `project-contract.json` and every canonical stable-version surface checked by CI.

## Preview means preview

Preview material may contain broader architecture and experimental capabilities. Documentation MUST keep preview status visible and MUST NOT describe preview-only contracts as already stable.

## Rollback

If a release promotion introduces a serious regression, do not rewrite history or silently relabel the same artifact. Publish a new corrective version or explicitly revert the promotion with preserved history and release notes.

## Long-horizon rule

Version numbers are part of the interoperability contract. Once third parties build against a public stable contract, convenience is not sufficient reason to reinterpret that version later.
