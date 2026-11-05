import test from "node:test";
import assert from "node:assert/strict";
import { createProviderExecutionState } from "../pilots/action-boundary/provider-execution-state.mjs";

const make = () => createProviderExecutionState({ operationId: "host-operation-1",
  proposalSha256: "a".repeat(64) });

test("provider milestones require separate host evidence references", () => {
  const run = make();
  for (const state of ["approved", "grant_consumed", "request_initiated",
    "provider_accepted", "completed", "independently_confirmed"]) {
    run.record(state, `host-evidence:${state}`);
  }
  const result = run.snapshot();
  assert.equal(result.state, "independently_confirmed");
  assert.equal(result.events.length, 6);
  assert.throws(() => run.record("completed", "rewrite"), /invalid_execution_transition/);
});

test("uncertainty is not completion and requires new evidence to reconcile", () => {
  const run = make();
  run.record("approved", "approval:1");
  run.record("grant_consumed", "claim:1");
  run.record("request_initiated", "outbound:1");
  const before = run.record("outcome_uncertain", "transport-timeout:1");
  assert.equal(before.state, "outcome_uncertain");
  assert.throws(() => run.record("completed", ""), /invalid_execution_transition/);
  run.record("provider_accepted", "reconciliation:provider-request-1");
  run.record("completed", "provider-completion:1");
  assert.equal(before.state, "outcome_uncertain");
  assert.equal(before.events.length, 4);
  assert.equal(run.snapshot().state, "completed");
});

test("denial, skipped stages, and malformed identities fail closed", () => {
  assert.throws(() => createProviderExecutionState({ operationId: "x", proposalSha256: "x" }));
  const run = make();
  assert.throws(() => run.record("completed", "invented"), /invalid_execution_transition/);
  run.record("blocked", "policy:deny");
  assert.throws(() => run.record("approved", "late"), /invalid_execution_transition/);
});
