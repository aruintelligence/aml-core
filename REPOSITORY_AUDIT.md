# Repository audit: aruintelligence/aml-core

**Date:** 16 November 2026, America/Los_Angeles (UTC-8)  
**Auditor scope:** read-only GitHub API and local tree. No settings were changed, and nothing was pushed.  
**Local branch:** `repo-standards`, based on `c8a2316fec6b508dab3c3d88b70eea13e38259ae` (fetched read-only from `directive010.bundle`).  
**Push URL:** `DISABLED-NO-PUSH`

This audit is about repository hygiene and GitHub project standards (Microsoft / AWS / Google open-source practice, the GitHub community profile, and OpenSSF Scorecard). It does not rediscuss product authorization vulnerabilities, and it does not describe weaknesses of any published snapshot.

## Current public score and gaps

OpenSSF Scorecard v5.6.0 was run against the **public** repository `github.com/aruintelligence/aml-core` (commit `79a24ba96820a4ca974bcba30b797bf35dd7abc7` as resolved by Scorecard).

**Aggregate public score: 5.5 / 10.**

| Check | Score | Public result |
|---|---:|---|
| Binary-Artifacts | 10 | No binaries found in the repo |
| Branch-Protection | 3 | Protection is not maximal on development and release branches |
| CI-Tests | 10 | 29/29 merged PRs had CI |
| CII-Best-Practices | 0 | No OpenSSF Best Practices badge effort detected |
| Code-Review | 0 | 0/29 approved changesets |
| Contributors | 3 | One contributing organization |
| Dangerous-Workflow | 10 | No dangerous workflow patterns detected |
| Dependency-Update-Tool | 0 | No Dependabot / Renovate config on the public default branch |
| Fuzzing | 0 | Not connected to a published fuzzing service |
| License | 10 | MIT license file present |
| Maintained | 10 | Recent commits and issue activity |
| Packaging | 10 | Packaging workflow detected |
| Pinned-Dependencies | 0 | GitHub Actions were pinned to moving tags (`@v4`, `@v5`) |
| SAST | 7 | CodeQL is present but not reported as running on all commits |
| Security-Policy | 10 | `SECURITY.md` is present |
| Signed-Releases | −1 | Scorecard did not treat existing GitHub releases as signed releases |
| Token-Permissions | 0 | Workflow tokens with excessive permissions (and missing permissions on at least one workflow) |
| Vulnerabilities | 10 | 0 known dependency vulnerabilities detected (alerts themselves are disabled in repo settings) |

GitHub community profile health was **85%**. Missing or undetected items: Code of Conduct, and the community-profile API reported no issue template even though specialized templates already existed (there was no `config.yml` or general bug/feature form).

### Settings and process gaps (unchanged until founder approval)

Read-only API snapshot (16 November 2026, America/Los_Angeles):

- Default branch is `main`. There is **no** branch named `development`.
- Classic branch-protection API returns “not protected” for `main`.
- Ruleset `22619580` (“Protect main”) is active but weak: pull requests are required, yet **0 approving reviews**, no code-owner review, and **no required status checks**. Deletion and non-fast-forward updates are blocked.
- Ruleset `26831396` is named as if it protected `development`, but it actually targets `operation-aml/grant-store-integrity-20261104` and requires CodeQL plus Pilot 003 checks.
- Secret scanning and push protection are **enabled**. Validity checks and non-provider patterns are disabled. Dependabot alerts and security updates are **disabled**. Private vulnerability reporting is **disabled**.
- Commit signoff and signed commits are not required. Delete-branch-on-merge is off.
- **447** branches exist. 24 open issues (mostly September 2026 challenge issues, unlabeled). 13 open pull requests, most of them drafts in a stack, including #470.
- Topics include `compiler` and `programming-language`, which oversell a research-prototype reference implementation.
- CI on the base tree tested Node 20 only, and only on PRs targeting `main`. No `package-lock.json` is in the repository.

## What was improved locally

All file-level work is on `repo-standards`. Product source and tests were not modified. A generated `package-lock.json` from a local `npm install` was discarded and not committed.

Community and documentation:

- README rewritten as an honest front door: research prototype / reference implementation, required stable and preview badges retained for existing contract checks, security-model summary, and no certification or general production-readiness claims.
- `SECURITY.md` updated with a private-reporting path, supported-version table, and acknowledgement goal, while preserving required baseline phrases.
- Added `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `SUPPORT.md`, issue forms (`bug-report.yml`, `feature-request.yml`, `config.yml`), Dependabot config, `.nvmrc`, `.editorconfig`, and `.gitattributes`.
- Expanded `CONTRIBUTING.md` with a local setup, `CODEOWNERS` community paths, the pull-request checklist, `docs/README.md` index, a short `GOVERNANCE.md` pointer, and a changelog hygiene note.
- Added `SETTINGS_CHANGE_PLAN.md` with exact `gh` commands that were **not** executed.

Workflow hardening (53 workflow files):

- Official Actions pinned to full commit SHAs: `actions/checkout@v4.4.0`, `setup-node@v4.4.0`, `setup-python@v5.6.0`, `setup-go@v5.6.0`, `upload-artifact@v4.6.2`. Existing `github/codeql-action` pins were left unchanged.
- Top-level least-privilege `permissions` added where missing (`conformance.yml`). Existing narrow permission blocks were kept, including write scopes on manual publish workflows.
- Concurrency groups added to every workflow. `cancel-in-progress` is false on write-capable or publish workflows.
- Job `timeout-minutes` set where missing (existing Pilot 003 and CodeQL timeouts kept).
- `ci.yml` now runs a Node.js **20 and 24** matrix (Python and Go verifier steps remain in the same job), and CI runs on all pull requests, not only those targeting `main`.

## Local Scorecard estimate (label: estimate)

Scorecard `--local` does not evaluate the same checks as a GitHub run (no Branch-Protection, Code-Review, CI-Tests, Maintained, Contributors, or Signed-Releases in this local run). The local aggregate of **7.7 / 10** is therefore **not comparable** to the public 5.5, and is only an estimate of file-detectable checks on this tree:

| Check | Public (default branch) | Local estimate (this tree) |
|---|---:|---:|
| Dependency-Update-Tool | 0 | 10 |
| Pinned-Dependencies | 0 | 9 |
| SAST | 7 | 10 |
| Security-Policy | 10 | 10 |
| Dangerous-Workflow | 10 | 10 |
| Token-Permissions | 0 | 0 |
| Fuzzing | 0 | 0 |

Once this branch is the default branch, a comparable public score would be expected to rise on **Pinned-Dependencies** and **Dependency-Update-Tool**. **Token-Permissions** remains 0 because the manual publish workflows still grant `contents: write` or `id-token: write` (necessary for release publication, and already restricted to `workflow_dispatch`). **Branch-Protection** and **Code-Review** will not move until the settings in `SETTINGS_CHANGE_PLAN.md` are approved and actually used. The local Binary-Artifacts dip (10 → 7) is treated as a `--local` scan artifact (working tree / install residue), not as binaries added to the repository.

## Verification

| Check | Result |
|---|---|
| Product / test code diff | None. `git diff --stat` against `c8a2316` is hygiene, docs, and workflow files only |
| actionlint 1.7.12 | 0 errors on all 53 workflow files |
| yamllint 1.38.0 (relaxed GHA config) | 0 errors on workflows, Dependabot, and issue forms |
| Offline Markdown link check | Passed across 458 Markdown files |
| `check-workflow-safety.mjs` | Pass |
| `check-project-contract.mjs` | Pass (85 checks) |
| `check-release-coherence.mjs` | Pass |
| `check-support-policy.mjs` | Pass |
| `check-security-baseline.mjs` | Pass |
| `npm test` Node v24.22.1 | 1495 tests, **1494 pass**, 0 fail, 1 skipped |
| `npm test` Node v20.19.5 | 1494 tests, **1493 pass**, 0 fail, 1 skipped |
| GitHub writes or pushes | None. Fetch-only API and `git fetch` from a local bundle. Push URL is `DISABLED-NO-PUSH` |

The private Directive 010 worktree and `directive010.bundle` were not modified.

## What still needs founder approval

See [SETTINGS_CHANGE_PLAN.md](SETTINGS_CHANGE_PLAN.md). In short: tighten the `main` ruleset (reviews and required checks), decide how to protect the real integration branch rather than inventing a `development` branch, enable private vulnerability reporting, enable Dependabot alerts, optionally require signed commits, clean 447 stale branches from a written list, and rewrite the public description/topics. Counsel or founder review is still required before any merge or additional public disclosure.

Raw logs, Scorecard JSON, and API snapshots are in `repo-standards-evidence/`.
