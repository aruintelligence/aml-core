#!/usr/bin/env node
// Finite-state specification of a one-use, revocation-aware host handoff.
// This checks the model's invariants; it does not prove an implementation.
import assert from "node:assert/strict";

const enc = state => JSON.stringify(state);
let states = 0, transitions = 0, cases = 0;

for (const matches of [[false, false], [false, true], [true, false], [true, true]]) {
  cases++;
  const initial = { grant: "issued", revoked: false, workers: ["idle", "idle"],
    executions: 0, executionsAtRevoke: null, last: "initial" };
  const pending = [initial];
  const seen = new Set();
  while (pending.length) {
    const state = pending.shift();
    const key = enc({ ...state, last: undefined });
    if (seen.has(key)) continue;
    seen.add(key);
    states++;
    assert.ok(state.executions <= 1, `one-use violation: ${enc(state)}`);
    assert.ok(state.workers.filter(x => x === "executed").length === state.executions);
    for (let i = 0; i < 2; i++) {
      if (!matches[i]) assert.ok(["idle", "blocked"].includes(state.workers[i]));
      if (state.workers[i] === "unknown") assert.equal(state.grant, "spent");
    }
    if (state.revoked) assert.equal(state.executions, state.executionsAtRevoke,
      `dispatch after revocation: ${enc(state)}`);
    const next = [];
    if (!state.revoked) next.push({ ...state, revoked: true,
      executionsAtRevoke: state.executions, last: "revoke" });
    for (let i = 0; i < 2; i++) {
      const move = (worker, rest, last) => {
        const workers = [...state.workers];
        workers[i] = worker;
        next.push({ ...state, ...rest, workers, last });
      };
      switch (state.workers[i]) {
        case "idle":
          move(matches[i] ? "approved" : "blocked", {}, matches[i] ? "approve" : "digest_mismatch");
          break;
        case "approved":
          if (state.grant === "issued" && !state.revoked) {
            move("consumed", { grant: "spent" }, "atomic_consume");
          } else move("blocked", {}, "claim_rejected");
          break;
        case "consumed":
          if (!state.revoked) move("executed", { executions: state.executions + 1 }, "dispatch");
          else move("blocked", {}, "revoked_before_dispatch");
          move("unknown", {}, "crash_after_consume");
          break;
      }
    }
    for (const successor of next) {
      transitions++;
      pending.push(successor);
    }
  }
}

console.log(JSON.stringify({ protocol: "aml-bounded-authorization-model-result/1",
  cases, states, transitions, invariants: ["at_most_one_execution",
    "digest_mismatch_blocks", "revocation_blocks_later_dispatch",
    "crash_does_not_reissue_grant"], result: "PASS",
  caveat: "Project-authored finite-state model; atomicity, trustworthy revocation, and guarded tool routing are assumptions." }, null, 2));
