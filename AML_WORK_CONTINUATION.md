# Operation ĀML continuation record

Date: 2026-11-04. Repository `aruintelligence/aml-core`. Baseline `main` SHA `79a24ba96820a4ca974bcba30b797bf35dd7abc7`; development branch `operation-aml/grant-store-integrity-20261104`; review [draft PR #468](https://github.com/aruintelligence/aml-core/pull/468). No main merge, release, production deployment or public website publication was authorized or performed. Local code/docs commits were `f0d3e2dbdaaf6b1bb779c7c150f24144a23184e5` and `01a8b67`; direct Git push lacked credentials, so the connected GitHub integration created a new remote commit `c22332942b632ae6f3be7cd490a2030cc8869a44` whose **tree SHA** `48b5ef468fbf008220561c226e19590feb0e6503` matched local commit `01a8b67` exactly. Subsequent continuation-document edits have their own branch head; inspect PR #468 for the current remote SHA. No existing main or tag history was rewritten.

## Preserved work

- Full 1,638-path baseline inventory: `audit/AML_REPOSITORY_INVENTORY.json`. Focused manual code audit and findings: `AML_COMPREHENSIVE_TECHNICAL_AUDIT.md`; it is not a line-by-line audit of every file.
- Fixed partial-store grant replay and inherited `toJSON`/array-method canonicalization hazards without changing normal `sorted-json-v1` bytes. New regression tests preserve the legacy negative fixture. Other loss and distributed threats remain open.
- Added controlled local outbox integration, bounded two-worker model, independent evaluation kit, specification and security reports. `AML_EXECUTION_INTEGRITY_SPEC.md` distinguishes callback return from provider acceptance/completion.
- Existing MIT license and tags untouched. Private IP, commercial, partner and paper drafts are stored separately from this public branch; do not accidentally add them.

## Results and precise limits

Baseline `npm test`: 1,090 pass / 0 fail. Final code `npm test`: 1,098 pass / 0 fail / 0 skipped. `npm run check:links`: 436 Markdown files passed at the first docs commit and 441 after the later docs edits. Cross-runtime action report: 13/13; Python vectors: six; local integration: one test with five scenarios; bounded model: four approval combinations, 110 states, 182 transitions. Local benchmark source commit `f0d3e2d...` and raw data: `audit/AML_ACTION_BENCHMARK_20261104.json`; run `node benchmarks/action-boundary.mjs` for another environment.

The complete `bash reproduction/action-boundary/reproduce.sh` **failed** in this session: a Perl verifier child timed out inside the aggregate stress check after earlier checks reported success (including an earlier 375/375 stress invocation). An isolated `node scripts/build-action-stress-matrix.mjs --check` rerun also **failed**, this time at `stress-ui-1-invalid-policy` because its Python child exceeded the hardcoded five-second `spawnSync` limit. The same case's Python adapter completed in 0.490 seconds when invoked alone, producing the expected `invalid_policy` denial. This supports transient runner/load sensitivity but does not establish its cause. Preserve both failures; investigate host conditions and per-child timing before changing a check. A first post-change full test found one compatibility failure; the implementation was corrected while preserving the negative test, and the final full suite passed.

## Next work in priority order

1. Resolve or reliably reproduce stress subprocess timeout with measured host load; preserve failing logs and distinguish resource contention from a code defect.
2. Run CI on the draft PR and examine every failure. Do not merge without founder authorization.
3. Add crash fault-injection at grant issue/claim and whole-store rollback scenarios; design external anchor and operator recovery.
4. Build a transactionally coordinated claim/revocation store under a documented single linearization point for multiple hosts.
5. Bind the exact provider request at dispatch, then add provider idempotency, acknowledgment and uncertain-outcome reconciliation.
6. Audit all effectful bypass routes and approver identity flows in one chosen integration.
7. Have an external engineer implement the verifier from `AML_ENGINEERING_CHALLENGE.md`; do not call in-repo Python independent.
8. Expand JSON/cross-runtime adversarial corpus for numeric, Unicode, depth, duplicate-key and resource-limit cases under an explicitly versioned protocol.
9. Complete full workflow, dependency, history secret and documentation audits; triage 28 open issues and four pre-existing PRs individually.
10. Founder and qualified counsel review public disclosures, contributor chain of title, trademarks, patent prior art, confidentiality/export and partner terms before release or private disclosure.

No background work continues after this session. Use the actual branch head and PR review state when resuming.

## Follow-up on draft PR #468

The initial PR head `e0ec8933f59ada3368956d2d44c058a8f8cd9069` completed 36 workflows successfully and two unsuccessfully. `Action boundary challenge` failed because the checked-in `docs/grant-directory-report.json` still contained the old `private_grant_directory_required` label for a symlinked claim path; the hardened store now fails closed with `grant_store_incomplete`. The generated report was refreshed (one changed reason), and `node scripts/build-grant-directory-report.mjs --check` passed all four historical/fixed scenarios. The remote follow-up commit is `40b2096c2a36ece18921e56786438bc6528e0555`. Its action-boundary challenge passed. `AML Consumer Compatibility` initially showed passing Linux/Windows and quickstart/typecheck jobs, while four macOS matrix jobs were cancelled with no failed test step; cause remains undetermined. On the follow-up commit, consumer compatibility was queued and CodeQL was in progress while 36 other workflows had passed. Inspect their final jobs before any merge.

An attempted additional canonicalizer hardening to reject accessor properties passed its targeted tests but failed the complete `npm test` suite because `test/guarded-tool-input.test.js` deliberately requires a getter to be read once and frozen for policy/callback. That uncommitted change and its new test were reverted; the branch retains the earlier tested implementation. Do not weaken the established regression. A future direct-caller design should specify whether accessor-bearing JavaScript objects are accepted or rejected, while preserving the guarded-tool snapshot contract and normal wire bytes.

The subsequent `test/action-boundary-file-grant.test.js` adds a torn issued-record fault case. It verifies a corrupt JSON grant produces a blocked receipt and zero callbacks or claim markers. Focused file-grant tests passed 10/10, and the full `npm test` suite passed **1,099/1,099**, zero fail/skipped. This changes no production code. Inspect PR #468's current head and CI before treating the new case as remotely verified.
