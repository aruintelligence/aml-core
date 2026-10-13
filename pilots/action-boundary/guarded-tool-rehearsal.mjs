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
    id: "host_allow", title: "Exact route, host allow rule",
    change: "The host's exact rule allows this local callback without an approval request or one-use claim.",
    host_move: "Reserve approval-free rules for deliberate host policy. Bind the actual destination to the rule and apply host authentication, audit, and operation idempotency where needed.",
    options: { rule: "allow" }
  },
  {
    id: "approved_route", title: "Exact route, simulated approval",
    change: "The host fixture approves the exact proposal and consumes its one-use claim.",
    host_move: "Replace the fixture hooks with an authenticated approval, a durable one-use claim, and the actual host service call.",
    options: {}
  },
  {
    id: "changed_destination", title: "Changed destination",
    change: "The requested destination is outside the one exact host rule.",
    host_move: "Derive the policy resource from the exact provider destination and keep the rule narrow.",
    options: { to: "other@example.test" }
  },
  {
    id: "mapper_mutated", title: "Host mapper mutates the proposal",
    change: "The host destination mapper changes its canonical argument snapshot. The adapter throws before producing a plan or dispatch receipt.",
    host_move: "Keep resourceFor synchronous and read-only. Treat mapper failures as host errors before planning; never present them as blocked dispatch receipts.",
    options: { mapper: "mutate" }
  },
  {
    id: "approval_unavailable", title: "No approval hook",
    change: "The host supplies no way to request approval.",
    host_move: "Supply an authenticated approval callback for approval-required rules, bound to this exact proposal.",
    options: { approval: "missing" }
  },
  {
    id: "approval_declined", title: "Approval request declined",
    change: "The approval fixture refuses the exact proposal. No one-use claim or tool callback runs.",
    host_move: "Treat a refusal as final for this attempt. A later attempt needs a new authenticated approval decision; never turn a refusal into an implicit grant.",
    options: { approval: "decline" }
  },
  {
    id: "approval_hook_error", title: "Approval hook throws after a local write",
    change: "The approval fixture writes an in-memory marker, then throws before returning a decision. No one-use claim or tool callback runs.",
    host_move: "Reconcile host authorization records after an approval hook error. A blocked tool receipt does not prove that the approval system recorded nothing; require a fresh verified decision for another attempt.",
    options: { approval: "throw_after_write" }
  },
  {
    id: "approval_mismatch", title: "Approval for another proposal",
    change: "The approval fixture returns a different proposal digest.",
    host_move: "Compare the approved digest with the frozen proposal before any claim or callback.",
    options: { approval: "mismatch" }
  },
  {
    id: "approval_reused", title: "One-use approval claimed twice",
    change: "The same proposal is attempted twice; the host consumes the claim once.",
    host_move: "Use an atomic, durable one-use grant store so a replay cannot invoke the callback again.",
    options: { repeat: true }
  },
  {
    id: "policy_revoked", title: "Rule revoked during approval",
    change: "The host removes the rule while the approval callback is pending.",
    host_move: "Recheck current host policy after asynchronous approval and before consuming a claim.",
    options: { approval: "revoke" }
  },
  {
    id: "arguments_mutated", title: "Caller changes the destination during approval",
    change: "The caller changes its original arguments after the proposal snapshot. The fixture callback still receives the approved destination.",
    host_move: "Capture canonical arguments once, then map and dispatch from that frozen proposal.",
    options: { approval: "mutate" }
  },
  {
    id: "claim_revoked", title: "Rule revoked during the one-use claim",
    change: "The host consumes the claim, then revokes the rule before dispatch. The callback stays untouched and the claim remains spent.",
    host_move: "Recheck policy after the claim; keep the consumed grant spent and require a fresh decision for another attempt.",
    options: { claim: "revoke" }
  },
  {
    id: "claim_hook_unknown", title: "Claim hook throws after consumption",
    change: "The fixture spends the one-use claim, then its claim hook throws before returning. Dispatch blocks without entering the tool callback.",
    host_move: "Reconcile the host grant store after a claim error. A blocked receipt does not prove that the one-use grant is still available.",
    options: { claim: "throw_after_consume" }
  },
  {
    id: "callback_unknown", title: "Callback throws after entry",
    change: "The local callback writes an in-memory fixture marker, then throws. The wrapper cannot claim that no side effect occurred.",
    host_move: "Record the uncertain result and use provider idempotency and reconciliation; never retry automatically from this receipt.",
    options: { callback: "throws" }
  },
  {
    id: "unknown_then_replay", title: "Unknown result, replay claim refused",
    change: "The callback writes one in-memory fixture marker, then throws. A second attempt using the same one-use fixture claim state blocks before callback entry.",
    host_move: "Reconcile the uncertain provider outcome before any new authorization. A spent grant cannot justify a retry; use host idempotency for the actual operation.",
    options: { callback: "throws", repeat: true }
  }
];

async function runFixture({ id, title, change, host_move, options }) {
  const policy = {
    protocol: "aml-action-policy/1",
    rules: [{ tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: options.rule !== "allow" }]
  };
  let approvalRequests = 0;
  let claimAttempts = 0;
  let claimsConsumed = 0;
  let callbackCount = 0;
  let fixtureStateChanges = 0;
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
      if (options.approval === "decline") {
        hookEvents.push("Fixture approval declined");
        return { approved: false };
      }
      if (options.approval === "throw_after_write") {
        fixtureStateChanges++;
        hookEvents.push("In-memory approval fixture marker written");
        hookEvents.push("Approval hook threw");
        throw new Error("simulated_approval_response_error");
      }
      hookEvents.push(options.approval === "mismatch" ? "Different digest returned" : "Matching digest returned");
      return { approved: true, proposal_sha256: options.approval === "mismatch" ? "0".repeat(64) : proposal_sha256 };
    };
  const guarded = createGuardedToolExecute({
    tool: "send_message", effect: "send", purpose: "Send a status update",
    resourceFor: mapped => {
      if (options.mapper === "mutate") {
        mapped.to = "other@example.test";
        hookEvents.push("Host mapper changed its argument snapshot");
      }
      return mapped.to;
    }, policy, requestApproval,
    consumeApproval: async () => {
      claimAttempts++;
      const accepted = claimAttempts === 1;
      if (accepted) claimsConsumed++;
      hookEvents.push(accepted ? "One-use claim consumed" : "One-use claim refused");
      if (options.claim === "revoke") {
        policy.rules = [];
        hookEvents.push("Host rule revoked after claim");
      }
      if (options.claim === "throw_after_consume") {
        hookEvents.push("Claim hook threw after consumption");
        throw new Error("simulated_claim_response_error");
      }
      return accepted;
    },
    execute: async args => {
      callbackCount++;
      hookEvents.push("Fixture callback entered");
      if (options.callback === "throws") {
        fixtureStateChanges++;
        hookEvents.push("In-memory fixture marker written");
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
    if (options.mapper === "mutate") {
      await assert.rejects(guarded(args), { name: "TypeError",
        message: "resourceFor must not mutate arguments" });
      return { adapter_error: "resourceFor must not mutate arguments",
        host_hook_events: [...hookEvents] };
    }
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
  return { id, title, change, host_move, destination: originalDestination,
    ...(options.approval === "mutate" ? { caller_destination_after_approval: args.to } : {}), attempts,
    approval_requests: approvalRequests, claim_attempts: claimAttempts, claims_consumed: claimsConsumed,
    callback_count: callbackCount, fixture_state_changes: fixtureStateChanges };
}

export async function buildGuardedToolRehearsal() {
  const cases = [];
  for (const fixture of fixtures) cases.push(await runFixture(fixture));
  return {
    protocol: "aml-guarded-tool-rehearsal/2",
    provenance: "project-authored local Node simulation",
    scope: "Fixture callbacks only. No message, human approval, provider call, or delivery evidence.",
    cases
  };
}

export function assertGuardedToolRehearsal(report) {
  const byId = Object.fromEntries(report.cases.map(item => [item.id, item]));
  const expected = {
    host_allow: [["allow", "dispatched", "host_dispatch_returned"], 1],
    approved_route: [["requires_approval", "dispatched", "host_dispatch_returned"], 1],
    changed_destination: [["deny", "blocked", "no_exact_rule"], 0],
    mapper_mutated: [0],
    approval_unavailable: [["requires_approval", "blocked", "approval_unavailable"], 0],
    approval_declined: [["requires_approval", "blocked", "approval_missing_or_mismatched"], 0],
    approval_hook_error: [["requires_approval", "blocked", "approval_error"], 0],
    approval_mismatch: [["requires_approval", "blocked", "approval_missing_or_mismatched"], 0],
    approval_reused: [
      ["requires_approval", "dispatched", "host_dispatch_returned"],
      ["requires_approval", "blocked", "approval_reused_or_expired"],
      1
    ],
    policy_revoked: [["requires_approval", "blocked", "policy_changed"], 0],
    arguments_mutated: [["requires_approval", "dispatched", "host_dispatch_returned"], 1],
    claim_revoked: [["requires_approval", "blocked", "policy_changed"], 0],
    claim_hook_unknown: [["requires_approval", "blocked", "approval_consume_error"], 0],
    callback_unknown: [["requires_approval", "unknown", "host_dispatch_error"], 1],
    unknown_then_replay: [
      ["requires_approval", "unknown", "host_dispatch_error"],
      ["requires_approval", "blocked", "approval_reused_or_expired"],
      1
    ]
  };
  assert.equal(report.cases.length, Object.keys(expected).length);
  for (const [id, values] of Object.entries(expected)) {
    const item = byId[id];
    assert.ok(item, `Missing case: ${id}`);
    assert.ok(typeof item.host_move === "string" && item.host_move.length > 20,
      `${id}: host design move`);
    const count = values.at(-1);
    const attempts = values.slice(0, -1);
    assert.equal(item.callback_count, count, `${id}: callback count`);
    if (id === "mapper_mutated") {
      assert.deepEqual(item.attempts, [{
        adapter_error: "resourceFor must not mutate arguments",
        host_hook_events: ["Host mapper changed its argument snapshot"]
      }]);
    } else {
      assert.deepEqual(item.attempts.map(({ policy_decision, execution_status, reason }) =>
        [policy_decision, execution_status, reason]), attempts, `${id}: receipts`);
      assert.ok(item.attempts.every(attempt => /^[0-9a-f]{64}$/.test(attempt.proposal_sha256)),
        `${id}: proposal digest`);
    }
  }
  assert.equal(byId.changed_destination.approval_requests, 0);
  assert.equal(byId.mapper_mutated.approval_requests, 0);
  assert.equal(byId.mapper_mutated.claim_attempts, 0);
  assert.equal(byId.host_allow.approval_requests, 0);
  assert.equal(byId.host_allow.claim_attempts, 0);
  assert.equal(byId.host_allow.claims_consumed, 0);
  assert.deepEqual(byId.host_allow.attempts[0].host_hook_events,
    ["Fixture callback entered", "Fixture callback returned"]);
  assert.equal(byId.approval_declined.approval_requests, 1);
  assert.equal(byId.approval_declined.claim_attempts, 0);
  assert.deepEqual(byId.approval_declined.attempts[0].host_hook_events,
    ["Approval requested", "Fixture approval declined"]);
  assert.equal(byId.approval_hook_error.approval_requests, 1);
  assert.equal(byId.approval_hook_error.claim_attempts, 0);
  assert.equal(byId.approval_hook_error.fixture_state_changes, 1);
  assert.deepEqual(byId.approval_hook_error.attempts[0].host_hook_events,
    ["Approval requested", "In-memory approval fixture marker written", "Approval hook threw"]);
  assert.equal(byId.approval_mismatch.claim_attempts, 0);
  assert.equal(byId.policy_revoked.claim_attempts, 0);
  assert.equal(byId.approval_reused.claim_attempts, 2);
  assert.equal(byId.approval_reused.claims_consumed, 1);
  assert.equal(byId.callback_unknown.attempts[0].result, undefined);
  assert.equal(byId.approved_route.fixture_state_changes, 0);
  assert.deepEqual(byId.changed_destination.attempts[0].host_hook_events, []);
  assert.deepEqual(byId.approval_unavailable.attempts[0].host_hook_events, []);
  assert.ok(byId.policy_revoked.attempts[0].host_hook_events.includes("Host rule revoked"));
  assert.ok(!byId.policy_revoked.attempts[0].host_hook_events.includes("Fixture callback entered"));
  assert.equal(byId.arguments_mutated.caller_destination_after_approval, "other@example.test");
  assert.equal(byId.arguments_mutated.attempts[0].result.would_send_to, "team@example.test");
  assert.ok(byId.arguments_mutated.attempts[0].host_hook_events.includes("Caller arguments changed after snapshot"));
  assert.equal(byId.claim_revoked.claim_attempts, 1);
  assert.equal(byId.claim_revoked.claims_consumed, 1);
  assert.deepEqual(byId.claim_revoked.attempts[0].host_hook_events.slice(-2),
    ["One-use claim consumed", "Host rule revoked after claim"]);
  assert.ok(!byId.claim_revoked.attempts[0].host_hook_events.includes("Fixture callback entered"));
  assert.equal(byId.claim_hook_unknown.claim_attempts, 1);
  assert.equal(byId.claim_hook_unknown.claims_consumed, 1);
  assert.deepEqual(byId.claim_hook_unknown.attempts[0].host_hook_events.slice(-2),
    ["One-use claim consumed", "Claim hook threw after consumption"]);
  assert.ok(!byId.claim_hook_unknown.attempts[0].host_hook_events.includes("Fixture callback entered"));
  assert.ok(byId.approval_reused.attempts[1].host_hook_events.includes("One-use claim refused"));
  assert.ok(!byId.approval_reused.attempts[1].host_hook_events.includes("Fixture callback entered"));
  assert.equal(byId.callback_unknown.fixture_state_changes, 1);
  assert.deepEqual(byId.callback_unknown.attempts[0].host_hook_events.slice(-3),
    ["Fixture callback entered", "In-memory fixture marker written", "Fixture callback threw"]);
  assert.equal(byId.unknown_then_replay.approval_requests, 2);
  assert.equal(byId.unknown_then_replay.claim_attempts, 2);
  assert.equal(byId.unknown_then_replay.claims_consumed, 1);
  assert.equal(byId.unknown_then_replay.callback_count, 1);
  assert.equal(byId.unknown_then_replay.fixture_state_changes, 1);
  assert.deepEqual(byId.unknown_then_replay.attempts[1].host_hook_events.slice(-1),
    ["One-use claim refused"]);
}

export function selectGuardedToolCase(report, id) {
  const selected = report.cases.find(item => item.id === id);
  if (!selected) throw new RangeError("Unknown guarded tool rehearsal case");
  return { protocol: report.protocol, provenance: report.provenance, scope: report.scope, case: selected };
}

export function listGuardedToolCases(report) {
  return report.cases.map(item =>
    `${item.id}\t${item.attempts.map(attempt => attempt.adapter_error ? "pre-plan error" : attempt.execution_status).join(" -> ")}`
  ).join("\n") + "\n";
}

export function parseGuardedToolArgs(args) {
  const [option, caseId] = args;
  if (!(args.length === 0 ||
      (args.length === 1 && ["--write", "--check", "--list"].includes(option)) ||
      (args.length === 2 && option === "--case" && fixtures.some(item => item.id === caseId)))) {
    throw new Error("Use no argument, --write, --check, --list, or --case <id> (see --list)");
  }
  return { option, caseId };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { option, caseId } = parseGuardedToolArgs(process.argv.slice(2));
  const report = await buildGuardedToolRehearsal();
  assertGuardedToolRehearsal(report);
  const json = JSON.stringify(report, null, 2) + "\n";
  if (option === "--write") {
    await writeFile(reportUrl, json, "utf8");
    console.log("Wrote docs/guarded-tool-rehearsal.json");
  } else if (option === "--check") {
    assert.equal(await readFile(reportUrl, "utf8"), json, "Rehearsal report is stale; run --write");
    console.log(`Guarded tool rehearsal: ${report.cases.length} cases match the checked-in report.`);
  } else if (option === "--list") {
    process.stdout.write(listGuardedToolCases(report));
  } else if (option === "--case") {
    process.stdout.write(JSON.stringify(selectGuardedToolCase(report, caseId), null, 2) + "\n");
  } else {
    process.stdout.write(json);
  }
}
