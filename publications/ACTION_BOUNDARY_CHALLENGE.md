# ĀML Action Boundary Challenge

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
node scripts/run-action-boundary-challenge.mjs -- ./your-adapter
```

The adapter command is one executable path. Use an executable wrapper script if your implementation needs an interpreter or build step. The runner appends the case file path, allows five seconds and 256 KiB of output per case, emits `aml-action-boundary-challenge-report/1` on stdout, and returns nonzero if any case fails. Keep diagnostics on stderr so stdout remains one JSON object.

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

Pin the Action to an immutable release tag or commit when recording a reproducible result. The caller owns the adapter and its executable permission. The Action outputs `passed`, `result-file`, `challenge-sha256`, and `vectors-sha256`. A failing challenge fails the step but still writes the report before exiting; upload the file as a workflow artifact if you want it available after a failed run.

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
