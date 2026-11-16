# GitHub settings change plan

**Repository:** [aruintelligence/aml-core](https://github.com/aruintelligence/aml-core)  
**Prepared:** 16 November 2026, America/Los_Angeles (UTC-8)  
**Scope:** proposed repository *settings* only. None of the commands in this file have been executed.

File-level improvements (README, community docs, workflow pinning, Dependabot config, issue forms) live on the local `repo-standards` branch and do not require these settings to be applied first. Settings changes below still need explicit founder approval. No merge, deploy, public push, external contact, or spending is authorized by this document.

Read-only inspection on 16 November 2026 (America/Los_Angeles) showed:

| Setting | Current state |
|---|---|
| Default branch | `main` |
| Classic branch protection on `main` | Not enabled (404) |
| Ruleset "Protect main" (`22619580`) | Active on the default branch. Prevents deletion and non-fast-forward updates. Requires a pull request, but **0 approving reviews**, no code-owner review, and **no required status checks** |
| Ruleset "Require AML security checks on development branch" (`26831396`) | Active, but it does **not** target a branch named `development`. It targets `refs/heads/operation-aml/grant-store-integrity-20261104` and requires CodeQL (JS/TS and Python) plus two Pilot 003 checks |
| Branch named `development` | Does not exist |
| Secret scanning / push protection | Enabled |
| Secret scanning validity checks and non-provider patterns | Disabled |
| Dependabot alerts | Disabled ("Vulnerability alerts are disabled") |
| Dependabot security updates | Disabled |
| Private vulnerability reporting | Disabled |
| Web commit signoff / signed commits | Not required |
| Delete branch on merge | Disabled |
| Discussions | Disabled |
| Open issues / PRs / branches | 24 open issues, 13 open PRs (most drafts), **447** branches |
| Topics / homepage | Homepage is the GitHub Pages site; topics include `compiler` and `programming-language`, which oversell the current research-prototype status |

## 1. Tighten the `main` ruleset (recommended first)

Keep the existing ruleset id `22619580` and raise it to a big-company baseline: at least one approving review, stale-review dismissal, code-owner review, conversation resolution, and required status checks for CI and CodeQL. Do not add bypass actors unless the founder names them.

Exact command (not executed):

```bash
gh api --method PUT repos/aruintelligence/aml-core/rulesets/22619580 \
  --input - <<'JSON'
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "required_reviewers": [],
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true,
        "required_review_thread_resolution_threshold": 0,
        "require_extra_approval_for_unattributed_changes": true,
        "allowed_merge_methods": ["squash", "rebase", "merge"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "test (20)", "integration_id": 15368 },
          { "context": "test (24)", "integration_id": 15368 },
          { "context": "CodeQL (javascript-typescript)", "integration_id": 15368 },
          { "context": "CodeQL (python)", "integration_id": 15368 }
        ]
      }
    },
    { "type": "required_signatures" }
  ]
}
JSON
```

Notes:

- Integration id `15368` is GitHub Actions, already used by ruleset `26831396`. Confirm the CI job names (`test (20)` and `test (24)`) from a green Actions run of the hardened `ci.yml` before requiring them, or the ruleset will block all merges.
- `required_signatures` requires signed commits. Enable it only if the founder and any other committers are prepared to sign. Until then, omit that one rule and use the optional signoff setting in section 5.
- Status-check names should be re-read from a successful workflow run; GitHub sometimes reports matrix jobs as `test (20)` or `CI / test (20)`.

## 2. Protect the real integration branch, not a fictional `development` branch

There is no `development` branch. The long-lived integration ref currently protected for security checks is `operation-aml/grant-store-integrity-20261104`.

Recommended options, in order:

1. Keep using that integration ref (or the branch that draft PR #470 actually targets) and extend ruleset `26831396` with a pull-request review rule, matching the `main` baseline.
2. If the founder wants a branch literally named `development`, create it explicitly from a reviewed commit *after* IP review, then retarget the ruleset. Do not create it casually; it would become a public head.

Exact command to inspect the current ruleset (read-only, safe to re-run):

```bash
gh api repos/aruintelligence/aml-core/rulesets/26831396
```

Exact command to add review requirements to that ruleset (not executed). Review the JSON from the GET first and send the full intended document, not a partial overwrite:

```bash
gh api --method PUT repos/aruintelligence/aml-core/rulesets/26831396 --input extended-development-ruleset.json
```

Do not point this ruleset at `main` in a way that drops the existing Pilot 003 checks until those jobs are also represented on `main`.

## 3. Enable private vulnerability reporting

`SECURITY.md` already tells reporters to use GitHub private reporting when it is available, and to email Office@aruintelligence.com until then. Enabling the feature is a settings change:

```bash
gh api --method PUT repos/aruintelligence/aml-core/private-vulnerability-reporting
```

To confirm afterwards (read-only):

```bash
gh api repos/aruintelligence/aml-core/private-vulnerability-reporting
```

## 4. Enable Dependabot alerts and security updates

A `.github/dependabot.yml` is in the tree so version-update PRs can be opened once alerts are on. Alerts themselves are still disabled.

```bash
gh api --method PUT repos/aruintelligence/aml-core/vulnerability-alerts
gh api --method PUT repos/aruintelligence/aml-core/automated-security-fixes
```

Optional, after alerts are on: confirm there is a plan for reviewing Dependabot PRs so they do not accumulate the way the 447 topic branches have.

## 5. Repository preferences

```bash
gh api --method PATCH repos/aruintelligence/aml-core \
  -F delete_branch_on_merge=true \
  -F web_commit_signoff_required=true \
  -F allow_auto_merge=false \
  -F allow_update_branch=true \
  -F has_wiki=false
```

`has_wiki=false` only if the founder confirms the wiki is unused. `web_commit_signoff_required` is a Developer Certificate of Origin-style checkbox; it is weaker than the signed-commit ruleset rule and can be enabled first.

Secret scanning is already on, including push protection. Optional tightening:

```bash
gh api --method PATCH repos/aruintelligence/aml-core \
  --input - <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning_validity_checks": { "status": "enabled" },
    "secret_scanning_non_provider_patterns": { "status": "enabled" }
  }
}
JSON
```

GitHub may require a UI confirmation or a different billing/plan flag for validity checks. If the API returns an error, use the repository Settings → Code security interface instead of retrying inventively.

## 6. Description, topics, and homepage

Recommended description (honest, no certification or production-readiness claim):

```text
ĀML is an open-source research prototype and reference implementation for inspectable policy and evidence around AI interfaces and host-owned agent actions.
```

```bash
gh repo edit aruintelligence/aml-core \
  --description "ĀML is an open-source research prototype and reference implementation for inspectable policy and evidence around AI interfaces and host-owned agent actions." \
  --homepage "https://aruintelligence.github.io/aml-core/" \
  --remove-topic compiler \
  --remove-topic programming-language \
  --remove-topic cognitive-architecture \
  --add-topic authorization \
  --add-topic supply-chain-security
```

Keep existing accurate topics such as `ai-agents`, `ai-safety`, `policy-engine`, `javascript`, `python`, `research`, and `open-source`. Do not add topics that imply a ratified standard or a certified product.

## 7. Stale branches (447 heads)

This is cleanup, not a settings toggle. Do **not** mass-delete branches that are heads of open PRs, including the stacked draft series around #468–#476, or any branch still needed for evidence or IP review.

A safe first step is a read-only inventory:

```bash
gh api repos/aruintelligence/aml-core/branches --paginate \
  --jq '.[].name' > branch-inventory.txt
```

Then, only after founder review of a written list, delete named stale branches one at a time:

```bash
# Example only — do not run against a list that has not been approved.
gh api --method DELETE repos/aruintelligence/aml-core/git/refs/heads/REPLACE_WITH_APPROVED_BRANCH
```

Prefixed groups observed on 16 November 2026 include many `codex/`, `feat/`, `feature/`, `fix/`, `bugfix/`, `release/`, and `launch/` heads. Several `release/` and `security/` branches date from September 2026 and may already be merged or abandoned. Confirm against open PRs before any deletion.

## 8. Issue and PR hygiene (no automatic close)

There are 24 open issues, mostly independent-verification challenges from September 2026, and 13 open PRs, most of them drafts in a stack. No issue or PR should be closed, labeled, or edited from this plan without a separate approval. Optional later work: add labels and a triage pass, and enable Discussions if the founder wants a non-issue Q&A forum.

```bash
gh api --method PATCH repos/aruintelligence/aml-core -F has_discussions=true
```

## 9. Signed releases, SBOM, and SLSA provenance

The repository already has package-reproducibility, SBOM, and some provenance workflows, plus manual `workflow_dispatch` publish jobs. Improving public signed-release posture is worthwhile, but it touches release keys, npm publication, and GitHub Environments. That is **not** a settings-only change and should not be done in the same approval batch as branch protection. Track it as follow-up after IP review of what may be published.

## Flags that need IP or counsel review before going public

- **Do not merge** the `repo-standards` work, or the broader draft PR #470 stack it may land on, until the founder (and counsel, if they so direct) says the public tree may receive it. Pushing to a draft PR is a separate, already discussed step; merging and tagging are not.
- **Do not describe** residual or historical authorization weaknesses of the currently published snapshot in README, issues, release notes, or topics. The local README states the intended authorization rule and ordinary trust assumptions only.
- **Do not publish** private research, patent-candidate write-ups, the DB-enforcement demo, or Directive 010 exploit evidence through this repository, Pages, or a release asset.
- Changing the public description, topics, Pages content, or launch-style copy should stay consistent with "research prototype / reference implementation" and must not imply certification, invention claims, or production readiness.
- Creating a `development` branch, adding a package lockfile, enabling npm automation, or attaching an OpenSSF Scorecard publishing workflow are public signals; do them only after the founder is comfortable with the visible tree.
- Contacting outside parties, buying a signing service, or filing anything with a standards body or patent office is out of scope here and remains unauthorized.

## Approval checklist

- [ ] Update ruleset `22619580` for `main` (reviews + status checks; signed commits optional)
- [ ] Decide how to protect the real integration branch (do not invent `development` casually)
- [ ] Enable private vulnerability reporting
- [ ] Enable Dependabot alerts and security updates
- [ ] Repository preferences (delete-branch-on-merge, signoff, optional wiki)
- [ ] Optional secret-scanning tightening
- [ ] Description and topics rewrite
- [ ] Written stale-branch deletion list, then deletions one by one
- [ ] Counsel or founder go-ahead before any merge or additional public disclosure
