# Action Contract Pilot 003 — stacked release and deployment boundary

Status: local review candidate. Current authorization is an isolated feature
branch and, only after independent-review findings are addressed and validation
is complete, publication as a **DRAFT PR to the existing development branch**.
**No merge anywhere and no deployment are authorized in this scope.** This is
not a release receipt, completed cloud CI run, npm publication or deployment
announcement. Do not commit/push/open the draft PR before review clearance.

## Correct branch and promotion boundary

The pilot is based on `operation-aml/grant-store-integrity-20261104` at
`cea832d4a8a3065684354c05975e3c121d3d4055`. Its first PR must target that
experimental branch, **not** `main`.

At release discovery, main was
`79a24ba96820a4ca974bcba30b797bf35dd7abc7`, and draft PR #468 contained 48
commits / 94 files (+14,379/-82) relative to main. Sending our current feature
branch directly to main includes those experimental ancestors wholesale. Do
not mark #468 ready, merge it, or promote its entire contents as a side effect
of releasing this bounded pilot. If either head advances, inspect and report
that divergence; do not silently reset/rebase the reviewed candidate.

## Checks for the stacked PR

[The dedicated workflow](../../.github/workflows/action-contract-pilot-003.yml)
accepts PRs whose **base** is main or the named experimental development branch.
It also runs after pushes/merges to those two branches. Expected job/check names:

- `pilot-003-atomic-acceptance`
- `pilot-003-full-regression`

The full-regression job also checks the repository security-baseline contract,
workflow permission policy and local documentation links. These are project
guards, not independent security certification. All root tests, including the
new authorization and negative-control cases, run without test-name filtering.
The atomic job explicitly runs both new Node test files. The second file invokes
18 review-derived Python cases (not 18 extra Node tests); the full suite discovers
the same wrapper automatically, so these cases cannot remain local-only evidence.

Both jobs run independently, without `needs`, success-only gating,
`continue-on-error`, path filters, a privileged environment or secrets. There is
no `pull_request_target` event. The ordinary pull-request checkout tests the
candidate merge context, not a hard-coded old source SHA. Checkout credentials
are not persisted. Contents permission is read-only. Actions use the repository's
existing major-version references: checkout v4, setup-node v4, setup-python v5;
these are not claimed to be immutable action-commit pins.

Node 20 and Python 3.12 match existing repository CI conventions; OpenSSL is
required. No dependency installation is added. Root package metadata currently
has no dependencies or install/test lifecycle hooks, and the jobs invoke
`node --test` directly rather than running arbitrary npm lifecycle hooks.

No path filter is deliberate. The pilot depends on shared authorization,
canonicalization, state reduction, status/history verification, Python fixtures,
package/test tooling and future dependencies. Enumerating only today's file
names risks a silently skipped job after tomorrow's change. Thus even unrelated
changes to either selected PR base run the two checks. `edited` also covers a
PR's base being changed into scope; it may rerun checks for title/body edits.
Draft PRs are not deliberately skipped. A move out of the allowed bases is out
of scope, not evidence that the pilot passed. Normal GitHub fork-workflow approval
policy still applies; do not bypass it.

Any future merge requires separate authorization; none is permitted now.
Main currently has a PR-required ruleset, but no required-status-check rule; the
experimental branch has no effective protection rules. A displayed green merge
button is therefore not the release gate. Check the **exact final head/merge
candidate**, both new check results, the independent review and any other
applicable existing checks before proposing any future merge. Do not equate old PR #468 checks with
checks of the new pilot. Do not weaken repository rules to merge.

## What deployment can and cannot mean

The verified existing hosted surface is GitHub Pages:
https://aruintelligence.github.io/aml-core/ . It builds **main `/docs`**, with
only main allowed for the github-pages environment. Static labs already exist.
A Python process and its retained provider-owned database cannot execute on
GitHub Pages. Merging this CLI fixture into development does not deploy a
provider, change the hosted labs, or expose a new service health endpoint.

Deployment is not authorized in this tranche. If it is separately requested
later, choose a concrete target first:

1. **Static evidence/demo lab:** a separate, truthful docs-only change on main
   can publish inspected evidence or a clearly labeled browser simulation via
   existing Pages. This needs a separately reviewed implementation/evidence
   artifact; it must not claim to execute the Python fixture in the browser.
2. **Experimental downloadable source/evidence:** publish an explicitly labeled
   reviewed artifact bound to its commit. This is distribution, not a running
   service or a stable package promotion.
3. **Hosted provider service:** no such deployment was established for this
   pilot. Hosting, ownership, authentication, protected retained storage, complete
   mediation, key management, operational rollback and service-level health
   checks need a concrete design and deployment target. Do not invent resources
   or treat an existing interface-evaluation server as this provider.

The npm workflow is not a shortcut: it publishes the canonical stable tag from
`project-contract.json` (currently v1.3.0), not the development candidate. The
last inspected npm publication attempt failed at its credential requirement;
no current live canonical npm package was verified. Never republish/relabel an
existing stable version to smuggle in this experimental code. Follow
[the release-promotion contract](../../RELEASE_PROMOTION.md) if a separate
versioned package promotion is later chosen.

## Rollback and preserved evidence

The following is a contingency plan for a separately authorized future merge,
not permission to merge now. Revert a merged pilot with a new reviewed PR to the experimental base; preserve
history and the failing experiment evidence. Do not force-reset branches,
retag stable releases or delete consumed authorization/effect/revocation records
as a deployment rollback. Persisted authority rollback can revive a grant.
A code rollback is not a data rollback or an undo of external effects.

A static Pages lab has its own docs-only revert PR against main; observe the
resulting Pages deployment status and verify the actual URLs after it completes.
That rollback need not and must not merge/revert all of PR #468. A future package
release needs a corrective version or explicit contract revert with preserved
history, not silent artifact replacement. A future hosted service needs its own
schema/state compatibility and retained-authority recovery plan before release.

## Reproducible evidence and disclosure review

A bounded local demo is the atomic acceptance suite:

```sh
node --test --test-timeout=120000 test/action-boundary-atomic-authorized-execution.test.js test/action-boundary-atomic-review-regressions.test.js
```

It generates only temporary synthetic keys/data, checks persisted rows rather
than trusting dispatch labels, and retains per-database one-use, check-time expiry,
provider-rollback/direct-administrator
bypass counterexamples. Passing this suite is evidence about those fixture
inputs and assumptions, not proof of universal authorization non-bypass, a
production host-compromise guarantee or real-world completion. See
[the pilot contract](ACTION_CONTRACT_PILOT_003.md) for its crash matrix and limits.

Before publishing the reviewed diff, verify that the PR contains only scoped
pilot code, CI and public release notes: no credentials, real issuer keys,
customer payloads, proprietary provider integration or unrelated frontier
invention/report material. Tests generate temporary keys; do not attach those
keys or temporary databases as public evidence. Public source publication and a
draft PR are disclosures, not confidential storage. The existing MIT license
permits broad reuse subject to its notice; it is not secrecy, novelty protection,
a security warranty or patent freedom-to-operate clearance. The provider-atomic
transaction is presented as established database engineering, not a patentable
new mechanism. Any later distinct unpublished invention needs founder/IP review
before being added to the public branch. This note is not legal advice.

## Corrected-candidate review gate

The first independent review reproduced two fix-before-publication issues:
SQLite filename URI confusion (trusted-path correctness/no-create) and test-only
ASCII DEL signer mismatch. The corrected candidate centralizes quoted SQLite
file URIs across the pilot and relevant legacy helpers, fixes the separate
ASCII-escaped test signer, and integrates review-derived cases into both checks.
It does not change the core signature profile, relax verification or remove the
legacy two-database counterexamples. The initial review did not cover later CI
edits or these corrections. Require a separate final check of the exact expanded
diff, workflow and reproduced results **before** any commit/push/draft PR. The
author's self-review is not that independent clearance. No merge or deployment
is permitted even after clearance under the current scope.
