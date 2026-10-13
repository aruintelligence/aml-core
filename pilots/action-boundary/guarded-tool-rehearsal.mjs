#!/usr/bin/env node
// Project-authored local fixtures. Every callback records or throws; none sends
// a message, authenticates a person, or contacts an outside service.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createGuardedToolExecute } from "./guarded-tool.mjs";

const reportUrl = new URL("../../docs/guarded-tool-rehearsal.json", import.meta.url);
const fixtures = [
  {
    id: "approved_route", title: "Exact route, simulated approval",
    change: "The host fixture approves the exact proposal and consumes its one-use claim.",
    options: {}
  },
  {
    id: "changed_destination", title: "Changed destination",
    change: "The requested destination is outside the one exact host rule.",
    options: { to: "other@example.test" }
  },
  {
    id: "approval_unavailable", title: "No approval hook",
    change: "The host supplies no way to request approval.",
    options: { approval: "missing" }
  },
  {
    id: "approval_mismatch", title: "Approval for another proposal",
    change: "The approval fixture returns a different proposal digest.",
    options: { approval: "mismatch" }
  },
  {
    id: "approval_reused", title: "One-use approval claimed twice",
    change: "The same proposal is attempted twice; the host consumes the claim once.",
    options: { repeat: true }
  },
  {
    id: "policy_revoked", title: "Rule revoked during approval",
    change: "The host removes the rule while the approval callback is pending.",
    options: { approval: "revoke" }
  },
  {
    id: "arguments_mutated", title: "Caller changes the destination during approval",
    change: "The caller changes its original arguments after the proposal snapshot. The fixture callback still receives the approved destination.",
    options: { approval: "mutate" }
  },
  {
    id: "claim_revoked", title: "Rule revoked during the one-use claim",
    change: "The host consumes the claim, then revokes the rule before dispatch. The callback stays untouched and the claim remains spent.",
    options: { claim: "revoke" }
  },
  {
    id: "callback_unknown", title: "Callback throws after entry",
    change: "The simulated callback throws, so the wrapper cannot assert the side effect did not occur.",
    options: { callback: "throws" }
  }
];

async function runFixture({ id, title, change, options }) {
  const policy = {
    protocol: "aml-action-policy/1",
    rules: [{ tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true }]
  };
  let approvalRequests = 0;
  let approvalConsumptions = 0;
  let callbackCount = 0;
  let hookEvents = [];
  const requestApproval = options.approval === "missing" ? undefined :
    async ({ proposal_sha256 }) => {
      approvalRequests++;
      hookEvents.push("Approval requested");
      if (options.approval === "revoke") {
        policy.rules = [];
        hookEvents.push("Host rule revoked");
      }
      if (options.approval === "mutate") {
        args.to = "other@example.test";
        hookEvents.push("Caller arguments changed after snapshot");
      }
      hookEvents.push(options.approval === "mismatch" ? "Different digest returned" : "Matching digest returned");
      return { approved: true, proposal_sha256: options.approval === "mismatch" ? "0".repeat(64) : proposal_sha256 };
    };
  const guarded = createGuardedToolExecute({
    tool: "send_message", effect: "send", purpose: "Send a status update",
    resourceFor: args => args.to, policy, requestApproval,
    consumeApproval: async () => {
      approvalConsumptions++;
      const accepted = approvalConsumptions === 1;
      hookEvents.push(accepted ? "One-use claim consumed" : "One-use claim refused");
      if (options.claim === "revoke") {
        policy.rules = [];
        hookEvents.push("Host rule revoked after claim");
      }
      return accepted;
    },
    execute: async args => {
      callbackCount++;
      hookEvents.push("Fixture callback entered");
      if (options.callback === "throws") {
        hookEvents.push("Fixture callback threw");
        throw new Error("simulated_callback_error");
      }
      hookEvents.push("Fixture callback returned");
      return { simulated: true, would_send_to: args.to };
    }
  });
  const args = { to: options.to || "team@example.test", body: "Build passed." };
  const originalDestination = args.to;
  async function attempt() {
    hookEvents = [];
    const { plan, receipt, result } = await guarded(args);
    return {
      policy_decision: plan.decision,
      proposal_sha256: plan.proposal_sha256,
      execution_status: receipt.execution_status,
      reason: receipt.reason,
      host_hook_events: [...hookEvents],
      ...(result ? { result } : {})
    };
  }
  const attempts = [await attempt()];
  if (options.repeat) attempts.push(await attempt());
  return { id, title, change, destination: originalDestination,
    ...(options.approval === "mutate" ? { caller_destination_after_approval: args.to } : {}), attempts,
    approval_requests: approvalRequests, approval_consumptions: approvalConsumptions,
    callback_count: callbackCount };
}

export async function buildGuardedToolRehearsal() {
  const cases = [];
  for (const fixture of fixtures) cases.push(await runFixture(fixture));
  return {
    protocol: "aml-guarded-tool-rehearsal/1",
    provenance: "project-authored local Node simulation",
    scope: "Fixture callbacks only. No message, human approval, provider call, or delivery evidence.",
    cases
  };
}

export function assertGuardedToolRehearsal(report) {
  const byId = Object.fromEntries(report.cases.map(item => [item.id, item]));
  const expected = {
    approved_route: [["requires_approval", "dispatched", "host_dispatch_returned"], 1],
    changed_destination: [["deny", "blocked", "no_exact_rule"], 0],
    approval_unavailable: [["requires_approval", "blocked", "approval_unavailable"], 0],
    approval_mismatch: [["requires_approval", "blocked", "approval_missing_or_mismatched"], 0],
    approval_reused: [
      ["requires_approval", "dispatched", "host_dispatch_returned"],
      ["requires_approval", "blocked", "approval_reused_or_expired"],
      1
    ],
    policy_revoked: [["requires_approval", "blocked", "policy_changed"], 0],
    arguments_mutated: [["requires_approval", "dispatched", "host_dispatch_returned"], 1],
    claim_revoked: [["requires_approval", "blocked", "policy_changed"], 0],
    callback_unknown: [["requires_approval", "unknown", "host_dispatch_error"], 1]
  };
  assert.equal(report.cases.length, Object.keys(expected).length);
  for (const [id, values] of Object.entries(expected)) {
    const item = byId[id];
    assert.ok(item, `Missing case: ${id}`);
    const count = values.at(-1);
    const attempts = values.slice(0, -1);
    assert.equal(item.callback_count, count, `${id}: callback count`);
    assert.deepEqual(item.attempts.map(({ policy_decision, execution_status, reason }) =>
      [policy_decision, execution_status, reason]), attempts, `${id}: receipts`);
    assert.ok(item.attempts.every(attempt => /^[0-9a-f]{64}$/.test(attempt.proposal_sha256)),
      `${id}: proposal digest`);
  }
  assert.equal(byId.changed_destination.approval_requests, 0);
  assert.equal(byId.approval_mismatch.approval_consumptions, 0);
  assert.equal(byId.policy_revoked.approval_consumptions, 0);
  assert.equal(byId.approval_reused.approval_consumptions, 2);
  assert.equal(byId.callback_unknown.attempts[0].result, undefined);
  assert.deepEqual(byId.changed_destination.attempts[0].host_hook_events, []);
  assert.deepEqual(byId.approval_unavailable.attempts[0].host_hook_events, []);
  assert.ok(byId.policy_revoked.attempts[0].host_hook_events.includes("Host rule revoked"));
  assert.ok(!byId.policy_revoked.attempts[0].host_hook_events.includes("Fixture callback entered"));
  assert.equal(byId.arguments_mutated.caller_destination_after_approval, "other@example.test");
  assert.equal(byId.arguments_mutated.attempts[0].result.would_send_to, "team@example.test");
  assert.ok(byId.arguments_mutated.attempts[0].host_hook_events.includes("Caller arguments changed after snapshot"));
  assert.equal(byId.claim_revoked.approval_consumptions, 1);
  assert.deepEqual(byId.claim_revoked.attempts[0].host_hook_events.slice(-2),
    ["One-use claim consumed", "Host rule revoked after claim"]);
  assert.ok(!byId.claim_revoked.attempts[0].host_hook_events.includes("Fixture callback entered"));
  assert.ok(byId.approval_reused.attempts[1].host_hook_events.includes("One-use claim refused"));
  assert.ok(!byId.approval_reused.attempts[1].host_hook_events.includes("Fixture callback entered"));
  assert.deepEqual(byId.callback_unknown.attempts[0].host_hook_events.slice(-2),
    ["Fixture callback entered", "Fixture callback threw"]);
}

export function selectGuardedToolCase(report, id) {
  const selected = report.cases.find(item => item.id === id);
  if (!selected) throw new RangeError("Unknown guarded tool rehearsal case");
  return { protocol: report.protocol, provenance: report.provenance, scope: report.scope, case: selected };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const report = await buildGuardedToolRehearsal();
  assertGuardedToolRehearsal(report);
  const json = JSON.stringify(report, null, 2) + "\n";
  if (process.argv[2] === "--write") {
    await writeFile(reportUrl, json, "utf8");
    console.log("Wrote docs/guarded-tool-rehearsal.json");
  } else if (process.argv[2] === "--check") {
    assert.equal(await readFile(reportUrl, "utf8"), json, "Rehearsal report is stale; run --write");
    console.log(`Guarded tool rehearsal: ${report.cases.length} cases match the checked-in report.`);
  } else if (process.argv[2] === "--case" && process.argv.length === 4) {
    process.stdout.write(JSON.stringify(selectGuardedToolCase(report, process.argv[3]), null, 2) + "\n");
  } else if (process.argv.length === 2) {
    process.stdout.write(json);
  } else {
    throw new Error("Use no argument, --write, --check, or --case <id>");
  }
}
