# Proposed action boundary — a small ĀML pilot

Agents can propose a tool call; the host must decide whether to dispatch it. This reference pilot freezes a proposed action as canonical JSON, hashes its exact semantics, checks an exact-match host policy, and binds a host approval to that proposal digest before dispatch. The execution callback receives the frozen proposal, even if the original object changes while approval is pending.

[**Open the Action Boundary Lab**](https://aruintelligence.github.io/aml-core/action-lab.html) to rehearse the proposal, rule, digest, simulated approval, and uncertain callback path in a browser. The lab's Web Crypto calculation is compared with all six published JavaScript vectors in CI; it is a project-authored mirror for this subset and does not call a tool or authenticate an approver.

[**Try the 13-case action-boundary challenge**](../../publications/ACTION_BOUNDARY_CHALLENGE.md) with your own executable adapter to publish a reproducible PASS, FAIL, or MIXED result. The challenge probes exact matching, approval binding, mutation during awaited approval, policy revocation, and uncertain dispatch. An outside witness requires an independently maintained implementation and public evidence; the included reference adapter is only a project self-test.

[**Wrap a function tool in your host**](../../docs/AGENT_TOOL_QUICKSTART.md) with `createGuardedToolExecute`, then run `node pilots/action-boundary/guarded-tool-demo.mjs` to see a simulated dispatch and a blocked destination change. The wrapper imports this project's reference boundary and is not an independent implementation.

[**Try a one-use grant replay**](https://aruintelligence.github.io/aml-core/action-lab.html?scenario=replay) or run `node pilots/action-boundary/one-shot-grant-demo.mjs`. The fixture issues one process-local grant for a digest. The first guarded call invokes the simulated callback; a second call with that same grant returns `approval_reused_or_expired` without invoking it again. This is a project-authored demonstration, not authenticated human approval or a durable distributed replay defense.

[**Inspect the two-process race**](https://aruintelligence.github.io/aml-core/approval-race.html) or run `node pilots/action-boundary/file-grant-race-demo.mjs`. This separate experimental store uses a host-owned directory on one local filesystem. Two Node child processes receive the same grant and compete to create its claim marker with an exclusive `wx` open. The recorded run shows exactly one simulated callback and a blocked reuse; the winning process can vary. The visual page plays back checked-in run data and does not start workers in the browser.

[**Compare JavaScript and Python case by case**](https://aruintelligence.github.io/aml-core/action-cross-runtime.html?case=mutated-while-awaiting). `python_boundary.py` implements the public plan/dispatch subset without importing the JavaScript reference; `challenge-python-adapter.py` exercises it as an external process against all 13 published cases. The checked-in visual report contains actual outputs from both project-maintained code paths, not just expected labels. Run `node scripts/build-action-cross-runtime-report.mjs --check` to regenerate and compare it. A passing internal adapter is not an independently maintained outside witness.

[**Explore the uncertain-dispatch ledger**](https://aruintelligence.github.io/aml-core/dispatch-ledger.html?scenario=crash) or run `node pilots/action-boundary/file-dispatch-ledger-demo.mjs`. A host supplies a stable operation ID and private absolute local directory. The ledger hashes the ID to select a record, binds that record to canonical proposal bytes, and creates an exclusive claim before invoking a simulated tool callback. Its separate six-scenario report is checked by `node scripts/build-file-dispatch-report.mjs --check` in CI. Two actual child processes race on one operation ID; a third exits after claiming, leaving a record that suppresses a retry. These are project-owned simulations.

[**Inspect the key-order counterexample**](https://aruintelligence.github.io/aml-core/key-order-lab.html?case=two-numeric-keys). The 13 fixtures did not exercise numeric-looking keys inside action arguments. The prior Python sort emitted `"10"` before `"2"`; JavaScript emits array-index `"2"` before `"10"` when stringifying its rebuilt ordinary object. The Python subset now mirrors those JavaScript bytes recursively. Run `node scripts/build-action-key-order-report.mjs --check` to see 519 exact JS/Python cases, old mismatch counts, and named edge cases. The corpus intentionally concentrates on troublesome keys and is not a representative failure-rate sample.

```bash
node pilots/action-boundary/demo.mjs
node pilots/action-boundary/boundary.test.mjs
node pilots/action-boundary/vectors.test.mjs
python3 pilots/action-boundary/verify_vectors.py
```

The demo simulates a message; it sends nothing. It shows three outcomes: an approval-required plan, a host-approved dispatch, and a blocked destination change. `boundary.mjs` exposes `planAction(proposal, policy)` and `dispatchAction(proposal, { policy, requestApproval, executeTool })`. The host owns the policy and both callbacks. Never take these from model output or untrusted tool descriptions.

The published [`vectors.json`](vectors.json) contains six exact proposal digests and decisions, including reordered keys, a changed destination, a changed body, and an undeclared effect. The dependency-free Python checker independently recomputes the selected vectors and rejects a tamper. It covers this fixture's JSON subset; it is **not** a general cross-language canonical JSON implementation. In particular, arbitrary JavaScript numbers and UTF-16 key ordering need a separately specified wire format before a broad interoperability claim.

The executable Python action boundary adds dispatch behavior for the same restricted wire subset: JSON integers within JavaScript's safe range, BMP-only object keys, and Unicode-scalar string values. Unsupported floats, non-BMP keys, and lone-surrogate values are rejected as `unsupported_json_subset` rather than silently producing a different digest. Numeric array-index object keys follow JavaScript's actual wire order: canonical decimal `0` through `4294967294` first in ascending numeric order; all remaining BMP keys in lexical order. This restriction is narrower than the JavaScript reference implementation; agreement is claimed only for the stated domain and checked cases, not every possible JSON input.

## Contract

```json
{
  "protocol": "aml-proposed-action/1",
  "tool": "send_message",
  "effect": "send",
  "resource": "team@example.test",
  "purpose": "Send a status update",
  "arguments": { "subject": "Update", "body": "The build passed." }
}
```

The separate policy has protocol `aml-action-policy/1` and exact rules with `tool`, `effect`, `resource`, and `requires_approval`. Unknown, malformed, and ambiguous policies deny. No wildcards or URL-prefix rules are supported. Supported effect labels are `read`, `write`, `send`, `pay`, and `delete`; they are declarations, not automatic classifications. The host must map the real tool and resource correctly. The host approval callback must return `{ approved: true, proposal_sha256 }` for the frozen proposal; an untrusted string with that shape is not proof of a person's consent.

The dispatch receipt records `blocked`, `dispatched`, or `unknown`. `dispatched` means the host callback returned; it does not prove delivery or completion. A callback error is `unknown` because a side effect might already have occurred; the boundary never retries it. SHA-256 detects changes in this proposal's canonical JSON, but does not authenticate the policy, approver, tool implementation, or external result.

An optional host-owned `consumeApproval` callback can atomically claim a grant after the digest matches and policy is rechecked, before the tool callback. It must return exactly `true` for a successful claim. A `false` result blocks with `approval_reused_or_expired`; a claim error blocks with `approval_consume_error`. Policy is checked again after an asynchronous claim. `createLocalOneShotGrants()` illustrates the contract in one Node process with expiry and a synchronous Map deletion. Production use needs a durable atomic store shared across workers, authenticated approval issuance, bounded expiry, audit storage, idempotency, and tool-specific authorization. The opt-in store does not protect unwrapped tools or other processes. This pilot does not replace those controls or the existing ĀML UI governance stack.

`createFileOneShotGrants({ directory })` is the next bounded step: a caller supplies a private **absolute path** to a trusted local filesystem shared by workers on one machine. Issuance writes a short-lived grant record (at most five minutes); a matching claim uses exclusive creation of a marker file. A competing process gets `false` and never reaches the callback. A crash after marker creation leaves the grant spent, even if no tool call occurred. The sample does not clean up issued or claimed records for a long-lived service. Do not put the directory on NFS, a network/synchronized mount, or a path writable by an untrusted user. Node documents that the exclusive flag may not work on network filesystems. The host still needs authenticated approvers, private storage, a trusted clock, lifecycle cleanup, recovery design, idempotency for external effects, and its own permission checks. These are project-authored tests, not independent verification or proof of delivery.

### Host-owned dispatch operation ledger (experimental)

`createFileDispatchLedger({ directory })` offers `claim`, `inspect`, and `run` for a **separate host-generated operation ID**. An approval grant answers whether this approval can be claimed once; the operation ID answers whether this particular intended external action has already been attempted. The host must persist the same ID across process restarts or retries, and must generate a new ID only for a genuinely new intent. Do not use the proposal digest alone as the ID: two separately authorized messages can have identical payloads. Never take the ID from model output.

The local directory must be private (owner-only, absolute, trusted local filesystem). `run({ operationId, proposal, executeTool })` freezes the proposal, claims with exclusive creation, and calls `executeTool` only for the winning claim. A duplicate sees `already_returned` or `unknown` without a callback; a changed proposal under the same ID is `mismatch`. The claim is synced before callback. A callback return writes a separate outcome record and yields `returned`; a callback throw yields `unknown`. If a process stops after claiming but before recording its outcome, subsequent attempts remain `unknown`. No success result is stored for replay and no retry occurs. An invalid or incomplete record fails closed. Outcome-write failure after a callback also yields `unknown`.

This utility is not wired to an untrusted agent directly. A host can put the ledger inside its existing `executeTool` callback and treat **anything other than the first `returned` result** as an uncertain boundary—not as permission to invoke the tool again. The receipt's `dispatched` status still means only that a callback returned. If an outside system supports true idempotency keys, use that service's contract too. This file store does not coordinate across machines, network mounts, or tools that bypass the wrapper, and does not implement retention or reconciliation. Permanent claims intentionally prefer missed execution over duplicate execution; investigate uncertain outcomes in the real external system before a human or host authorizes a fresh ID. No human authentication, payment, or delivery is supplied here.

## Why this wedge

Existing agent frameworks provide guardrails, approvals, and traces. Their paths and coverage differ by tool and handoff type. A portable, inspectable action proposal can make the **exact bytes being approved and dispatched** easier to compare across hosts. This is a project-authored interoperability experiment, not a claim of a new industry standard or independent validation. See the [OpenAI Agents SDK tool guardrail documentation](https://openai.github.io/openai-agents-python/guardrails/) and [tool documentation](https://openai.github.io/openai-agents-js/guides/tools/) for examples of current framework controls.

