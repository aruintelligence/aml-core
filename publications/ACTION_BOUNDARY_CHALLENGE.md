# ĀML Action Boundary Challenge

The [expanded 100-case challenge](ACTION_BOUNDARY_EXPANDED_CHALLENGE.md) publishes full proposal/policy fixtures, simulated evidence receipts, receipt hashes, and JavaScript/Python replay checks while preserving this original 13-case interoperability contract.

**Status: project-authored challenge; outside implementations and witnesses are invited.**

This challenge asks a narrow, reproducible question: can another implementation freeze a proposed tool call, match the exact host policy, bind approval to the proposal digest, and report the dispatch boundary accurately? It runs only simulated host callbacks and never supplies a live tool or a person's approval.

The [machine contract](../conformance/action-boundary-challenge.json), [six digest vectors](../pilots/action-boundary/vectors.json), and [pilot description](../pilots/action-boundary/README.md) define this version. The harness records SHA-256 hashes of the exact manifest and vector file bytes in its report.

## Implement one adapter

Supply an executable in your own repository. The harness calls it once for each case:

```text
<adapter-command> <case.json>
```

`case.json` contains `protocol: "aml-action-challenge-case/1"`, a `case_id`, a `proposal`, a `policy`, and a simulated `host` fixture. The adapter must print **one JSON object** to stdout and exit `0` for a valid response, including blocked and unknown outcomes:

```json
{
  "protocol": "aml-action-boundary-result/1",
  "plan": {
    "protocol": "aml-action-plan/1",
    "proposal_sha256": "<64 lowercase hex characters or null>",
    "decision": "requires_approval",
    "reason": "exact_rule"
  },
  "receipt": {
    "protocol": "aml-action-dispatch/1",
    "proposal_sha256": "<same digest or null>",
    "policy_decision": "requires_approval",
    "execution_status": "dispatched",
    "reason": "host_dispatch_returned"
  },
  "tool_calls": 1,
  "executed_proposal": "<the exact proposal object handed to the simulated tool, or null>"
}
```

The example uses placeholders, not a runnable result. Read the manifest for each case's expected values. `proposal_sha256` is the SHA-256 of canonical JSON for the frozen proposal. This pilot uses JavaScript's canonical JSON routine; the published Python checker covers the *selected fixture subset*, not arbitrary cross-language JSON. Preserve exact string values and the proposal given to the simulated tool. Object member order may differ in the returned `executed_proposal`.

Host fixture behavior:

| Field | Meaning |
|---|---|
| `approval: "matching"` | Return `{ approved: true, proposal_sha256 }` for the frozen proposal. |
| `approval: "fixed"` | Return the supplied `approval_digest_sha256`; this can be stale. |
| `approval: "missing"` | No approval callback exists. |
| `approval: "throw"` | The approval callback fails. |
| `mutate_proposal_body` | During awaited approval, change the caller's proposal body and the callback's copy. Dispatch must still use the original frozen proposal. |
| `remove_policy_rule: true` | During awaited approval, remove all host policy rules before dispatch. |
| `tool: "return"` | The simulated tool returns successfully. |
| `tool: "throw"` | The simulated tool throws after invocation; outcome is `unknown`, with exactly one tool call and no automatic retry. |

The host fixture is test data, not model-provided authority. In a real host, the host must own its tool mapping, policy, approval callback, and execution callback. A digest alone does not authenticate a person.

## Run it

From a checkout of this repository:

```bash
node scripts/run-action-boundary-challenge.mjs --case changed-destination -- ../my-adapter/adapter
node scripts/run-action-boundary-challenge.mjs -- ../my-adapter/adapter
node scripts/run-action-boundary-challenge.mjs --html-out ./my-boundary-run.html -- ../my-adapter/adapter
node scripts/run-action-boundary-challenge.mjs --probes --html-out ./my-probed-run.html -- ../my-adapter/adapter
```

Keep your adapter in its own repository, adjacent to this checkout, and replace the example sibling path. The adapter command is one executable path. Use an executable wrapper script if your implementation needs an interpreter or build step. The runner appends the case file path, allows five seconds and 256 KiB of output per case, emits `aml-action-boundary-challenge-report/1` on stdout, and returns nonzero if any selected case fails. Keep adapter diagnostics on stderr so its stdout remains one JSON object.

Start with `--case <id>` to shorten the edit/run loop. A failed case keeps the stable `failures` codes and adds `diagnostics` with each mismatched field's expected and observed JSON previews. An invalid case ID exits with code 2. The JSON report identifies `case_scope` (`single` or `full`), `selected_case`, and `full_challenge_passed`. A focused PASS sets `passed: true` for that one case but **always** sets `full_challenge_passed: false`. Run without `--case` before reporting full compatibility. The [visual challenge board](https://aruintelligence.github.io/aml-core/action-challenge.html?case=changed-destination#cases) offers a shareable link and copyable command for every case; it shows expected fixtures, not your observed results.

**Test beyond memorized answers:** `--probes` adds six project-defined follow-up cases to the 13 published fixtures. A fresh random 128-bit seed changes body bytes, purpose, resources, and one exact policy rule for every run. The report records `probe_seed`, `published_case_count`, and `probe_case_count`; reproduce a run with `--probes --probe-seed <the 32 lowercase hex characters>`. `--case` and `--probes` are mutually exclusive. The Action enables these probes by default, so its full run has 19 cases. The fixed 13-case mode remains available for development and older adapters. The transformations are public in [`action-boundary-probes.js`](../conformance/action-boundary-probes.js); they are not secret tests and cannot prove that an adapter has no hardcoded shortcuts. [Inspect the 13/13 false signal and 13/19 counterexample](https://aruintelligence.github.io/aml-core/action-probe-lab.html), including the [machine report](../docs/action-probe-report.json).

`--html-out <new-file.html>` also writes a self-contained offline visual report of **your actual run**. The JSON report still goes to stdout and the process still exits nonzero on a failed case. The HTML shows PASS, FAIL, or MIXED, scope, stable failure codes, expected/observed diagnostics, and the manifest/vector hashes. It loads no third-party assets or network data. An existing output path is never overwritten; use a new path for each run. Keep the generated HTML with your adapter's commit and JSON report. This is a readable view, not a signed attestation or automatic proof of independent provenance. [Open the published project reference example](https://aruintelligence.github.io/aml-core/action-challenge-run.html) to see the format; its 13/13 result is explicitly a self-test, not an outside implementation.

A **project-maintained Python example** can be run directly with `node scripts/run-action-boundary-challenge.mjs -- python3 pilots/action-boundary/challenge-python-adapter.py`. It implements the published subset without importing the JavaScript boundary. The [visual cross-runtime comparison](https://aruintelligence.github.io/aml-core/action-cross-runtime.html) shows both actual outputs per case. This example demonstrates interoperability engineering but does **not** qualify as an outside witness; maintain an external implementation for that claim. Python rejects floats, non-BMP object keys, and lone-surrogate values rather than claiming general JavaScript JSON canonicalization. A [numeric-key counterexample and repair](https://aruintelligence.github.io/aml-core/key-order-lab.html) expands the regression beyond these 13 cases.

In an outside repository's GitHub Actions workflow:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: "22"
- id: boundary
  uses: aruintelligence/aml-core/actions/action-boundary-conformance@main
  with:
    adapter-command: ./your-adapter
- run: cat "${{ steps.boundary.outputs.result-file }}"
```

Pin the Action to an immutable release tag or commit when recording a reproducible result. The caller owns the adapter and its executable permission. The Action outputs `passed`, `result-file`, `html-file`, `artifact-url`, `challenge-sha256`, and `vectors-sha256`. The Action posts a per-case job summary and uploads the JSON and standalone HTML as one workflow artifact **before** failing a mismatched run. Open the workflow run's summary to see the cases and download both reports, including when the adapter fails. GitHub's artifact retention and access settings apply. The output paths exist only on that job's runner. This Action uses `actions/upload-artifact@v4`, so the automatic artifact path is intended for GitHub.com Actions; GitHub Enterprise Server support must be evaluated separately.
The Action runs the full 19-case suite with a fresh seed; `--case` is an interactive local development option. Each workflow artifact records its own seed, so compare like-for-like inputs when comparing results.

## What the 13 cases exercise

| Case | Required behavior |
|---|---|
| `approved-send`, `reordered-keys` | Approve and dispatch the frozen proposal; order of JSON object keys does not change its digest. |
| `changed-destination`, `undeclared-effect` | Deny an action lacking an exact host rule. |
| `stale-body-approval`, `missing-approval`, `approval-error` | Block dispatch without a matching host approval. |
| `allowed-read` | Dispatch a read allowed by the host rule without approval. |
| `mutated-while-awaiting` | Dispatch only the frozen original, even after caller and callback copies change. |
| `policy-revoked-while-awaiting` | Recheck the host policy and block dispatch after revocation. |
| `dispatch-uncertain` | Record `unknown` after a throwing tool callback and do not retry. |
| `ambiguous-policy`, `malformed-proposal` | Deny and use a null digest for malformed input or ambiguous policy. |

The included [`challenge-reference-adapter.mjs`](../pilots/action-boundary/challenge-reference-adapter.mjs) imports the project reference boundary. CI runs it to test the harness, but **that run is project-authored**. `node scripts/run-action-boundary-challenge.mjs --self-test` provides the same in-process check where subprocess creation is unavailable and explicitly marks the report `project_reference_self_test: true`.

For an outside witness, maintain your implementation and its result outside `aruintelligence/aml-core`; do not import or wrap `pilots/action-boundary/boundary.mjs`. Publish PASS, FAIL, or MIXED with your source, exact challenge and vector hashes, runtime, command, and workflow log or report. A failed case or an ambiguous contract is useful evidence. You can submit a result through the repository's [independent verification issue](https://github.com/aruintelligence/aml-core/issues/88).

**Claim boundary:** PASS shows compatibility with these project-defined cases. It does not prove the adapter is independent, that an external effect happened, that a human consented, or that the protocol is a standard, certified, or suitable for production authorization. Independent maintenance and evidence require separate review.
