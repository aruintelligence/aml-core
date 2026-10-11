# Proposed action boundary — a small ĀML pilot

Agents can propose a tool call; the host must decide whether to dispatch it. This reference pilot freezes a proposed action as canonical JSON, hashes its exact semantics, checks an exact-match host policy, and binds a host approval to that proposal digest before dispatch. The execution callback receives the frozen proposal, even if the original object changes while approval is pending.

[**Open the Action Boundary Lab**](https://aruintelligence.github.io/aml-core/action-lab.html) to rehearse the proposal, rule, digest, simulated approval, and uncertain callback path in a browser. The lab's Web Crypto calculation is compared with all six published JavaScript vectors in CI; it is a project-authored mirror for this subset and does not call a tool or authenticate an approver.

[**Try the 13-case action-boundary challenge**](../../publications/ACTION_BOUNDARY_CHALLENGE.md) with your own executable adapter to publish a reproducible PASS, FAIL, or MIXED result. The challenge probes exact matching, approval binding, mutation during awaited approval, policy revocation, and uncertain dispatch. An outside witness requires an independently maintained implementation and public evidence; the included reference adapter is only a project self-test.

```bash
node pilots/action-boundary/demo.mjs
node pilots/action-boundary/boundary.test.mjs
node pilots/action-boundary/vectors.test.mjs
python3 pilots/action-boundary/verify_vectors.py
```

The demo simulates a message; it sends nothing. It shows three outcomes: an approval-required plan, a host-approved dispatch, and a blocked destination change. `boundary.mjs` exposes `planAction(proposal, policy)` and `dispatchAction(proposal, { policy, requestApproval, executeTool })`. The host owns the policy and both callbacks. Never take these from model output or untrusted tool descriptions.

The published [`vectors.json`](vectors.json) contains six exact proposal digests and decisions, including reordered keys, a changed destination, a changed body, and an undeclared effect. The dependency-free Python checker independently recomputes the selected vectors and rejects a tamper. It covers this fixture's JSON subset; it is **not** a general cross-language canonical JSON implementation. In particular, arbitrary JavaScript numbers and UTF-16 key ordering need a separately specified wire format before a broad interoperability claim.

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

The dispatch receipt records `blocked`, `dispatched`, or `unknown`. `dispatched` means the host callback returned; it does not prove delivery or completion. A callback error is `unknown` because a side effect might already have occurred; the boundary never retries it. SHA-256 detects changes in this proposal's canonical JSON, but does not authenticate the policy, approver, tool implementation, or external result. A production host needs authentication, durable audit storage, replay controls, approval expiry, idempotency, and tool-specific authorization. This pilot does not replace those controls or the existing ĀML UI governance stack.

## Why this wedge

Existing agent frameworks provide guardrails, approvals, and traces. Their paths and coverage differ by tool and handoff type. A portable, inspectable action proposal can make the **exact bytes being approved and dispatched** easier to compare across hosts. This is a project-authored interoperability experiment, not a claim of a new industry standard or independent validation. See the [OpenAI Agents SDK tool guardrail documentation](https://openai.github.io/openai-agents-python/guardrails/) and [tool documentation](https://openai.github.io/openai-agents-js/guides/tools/) for examples of current framework controls.

