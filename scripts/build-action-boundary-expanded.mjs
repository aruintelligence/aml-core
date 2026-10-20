#!/usr/bin/env node
// Deterministic, project-authored fixture generator. Expected results are
// specified here, never copied from the implementation under test.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const casesUrl = new URL("../conformance/action-boundary-expanded-cases.json", import.meta.url);
const receiptsUrl = new URL("../conformance/action-boundary-expanded-receipts.jsonl", import.meta.url);
const hash = value => crypto.createHash("sha256").update(canonicalJSONStringify(value), "utf8").digest("hex");
const copy = value => structuredClone(value);
const rule = (tool, effect, resource, requires_approval) =>
  ({ tool, effect, resource, requires_approval });

const seeds = [
  { id: "mail", tool: "send_message", effect: "send", resource: "team@example.test",
    approval: true, arguments: { to: "team@example.test", cc: [], subject: "Update",
      body: "The build passed.", metadata: { z: 2, a: ["é", true, null] } } },
  { id: "read", tool: "fetch_record", effect: "read", resource: "record:42",
    approval: false, arguments: { path: "record:42", fields: ["owner", "summary"], functionCallId: "read-042" } },
  { id: "write", tool: "write_record", effect: "write", resource: "record:42",
    approval: true, arguments: { path: "record:42", value: { owner: "Ada", status: "draft" }, functionCallId: "write-042" } },
  { id: "pay", tool: "request_payment", effect: "pay", resource: "invoice:42",
    approval: true, arguments: { account: "invoice:42", amount_cents: 4200, currency: "USD", functionCallId: "pay-042" } },
  { id: "delete", tool: "delete_record", effect: "delete", resource: "record:42",
    approval: true, arguments: { path: "record:42", reason: "Duplicate draft", functionCallId: "delete-042" } },
  { id: "http", tool: "http_request", effect: "read", resource: "https://api.example.test/v1/status",
    approval: false, arguments: { url: "https://api.example.test/v1/status", method: "GET", headers: { Accept: "application/json" } } },
  { id: "ui", tool: "render_ui", effect: "write", resource: "screen:home",
    approval: false, arguments: { root: "#app", html: "<p>Welcome</p>", functionCallId: "render-001" } }
];

const rows = [];
function add(id, seed, configure = () => {}, intent = "") {
  const proposal = { protocol: "aml-proposed-action/1", tool: seed.tool, effect: seed.effect,
    resource: seed.resource, purpose: `Challenge ${seed.id}`, arguments: copy(seed.arguments) };
  const policy = { protocol: "aml-action-policy/1", rules: [rule(seed.tool, seed.effect, seed.resource, seed.approval)] };
  const host = { approval: seed.approval ? "matching" : "missing", tool: "return" };
  const scenario = { proposal, policy, host, decision: seed.approval ? "requires_approval" : "allow",
    reason: "exact_rule", status: "dispatched", receipt_reason: "host_dispatch_returned", tool_calls: 1 };
  configure(scenario);
  const input = scenario.proposal;
  const digest = scenario.reason === "invalid_proposal" || scenario.reason === "ambiguous_policy" ||
    scenario.reason === "invalid_policy" ? null : hash(input);
  const plan = { protocol: "aml-action-plan/1", proposal_sha256: digest,
    decision: scenario.decision, reason: scenario.reason };
  const receipt = { protocol: "aml-action-dispatch/1", proposal_sha256: digest,
    policy_decision: scenario.decision, execution_status: scenario.status, reason: scenario.receipt_reason };
  const expected = { plan, receipt, tool_calls: scenario.tool_calls,
    executed_proposal: scenario.tool_calls ? copy(input) : null };
  const caseId = `${seed.id}-${id}`;
  rows.push({ protocol: "aml-action-expanded-case/1", id: caseId, intent,
    proposal: input, policy: scenario.policy, host: scenario.host, expected,
    receipt_schema: "protocol/action-boundary-evidence-receipt.schema.json" });
}

const reverse = value => Object.fromEntries(Object.entries(value).reverse());
for (const seed of seeds) {
  add("baseline", seed, undefined, "Exact rule and frozen payload reach the simulated callback.");
  add("reordered-keys", seed, s => {
    const reversed = reverse(s.proposal);
    for (const key of Object.keys(s.proposal)) delete s.proposal[key];
    Object.assign(s.proposal, reversed);
    s.proposal.arguments = reverse(s.proposal.arguments);
  }, "Key order changes neither digest nor decision.");
  add("changed-payload", seed, s => {
    s.proposal.arguments.note = "Payload changed after the original digest";
    if (seed.approval) {
      s.host = { approval: "fixed", approval_digest_sha256: hash({ protocol: "aml-proposed-action/1",
        tool: seed.tool, effect: seed.effect, resource: seed.resource,
        purpose: `Challenge ${seed.id}`, arguments: copy(seed.arguments) }), tool: "return" };
      Object.assign(s, { status: "blocked", receipt_reason: "approval_missing_or_mismatched", tool_calls: 0 });
    }
  }, "Changed payload with an old grant blocks an approval-required action; an allow rule has no grant to mismatch.");
  add("changed-resource", seed, s => {
    s.proposal.resource = `other:${seed.id}`;
    Object.assign(s, { decision: "deny", reason: "no_exact_rule", status: "blocked",
      receipt_reason: "no_exact_rule", tool_calls: 0 });
  }, "Changed declared resource has no exact host rule.");
  add("changed-tool", seed, s => {
    s.proposal.tool = `other_${seed.tool}`;
    Object.assign(s, { decision: "deny", reason: "no_exact_rule", status: "blocked",
      receipt_reason: "no_exact_rule", tool_calls: 0 });
  }, "Changed tool has no exact host rule.");
  add("changed-effect", seed, s => {
    s.proposal.effect = seed.effect === "read" ? "write" : "read";
    Object.assign(s, { decision: "deny", reason: "no_exact_rule", status: "blocked",
      receipt_reason: "no_exact_rule", tool_calls: 0 });
  }, "Changed effect has no exact host rule.");
  add("callback-throws", seed, s => {
    s.host.tool = "throw";
    Object.assign(s, { status: "unknown", receipt_reason: "host_dispatch_error" });
  }, "A throwing callback has uncertain external outcome and exactly one invocation.");
  add("duplicate-policy", seed, s => {
    s.policy.rules.push(copy(s.policy.rules[0]));
    Object.assign(s, { decision: "deny", reason: "ambiguous_policy", status: "blocked",
      receipt_reason: "ambiguous_policy", tool_calls: 0 });
  }, "Ambiguous exact rules fail closed with a null plan digest.");
  add("extra-proposal-field", seed, s => {
    s.proposal.undeclared = true;
    Object.assign(s, { decision: "deny", reason: "invalid_proposal", status: "blocked",
      receipt_reason: "invalid_proposal", tool_calls: 0 });
  }, "Unexpected proposal field fails closed with a null plan digest.");
  add("invalid-policy-protocol", seed, s => {
    s.policy.protocol = "other-policy/1";
    Object.assign(s, { decision: "deny", reason: "invalid_policy", status: "blocked",
      receipt_reason: "invalid_policy", tool_calls: 0 });
  }, "An invalid host policy fails closed with a null plan digest.");
  add("different-policy-resource", seed, s => {
    s.policy.rules[0].resource = `different:${seed.id}`;
    Object.assign(s, { decision: "deny", reason: "no_exact_rule", status: "blocked",
      receipt_reason: "no_exact_rule", tool_calls: 0 });
  }, "A valid rule for a different resource cannot authorize this proposal.");
  if (seed.approval) {
    add("missing-approval", seed, s => {
      s.host.approval = "missing";
      Object.assign(s, { status: "blocked", receipt_reason: "approval_unavailable", tool_calls: 0 });
    }, "Missing host approval hook blocks execution.");
    add("approval-error", seed, s => {
      s.host.approval = "throw";
      Object.assign(s, { status: "blocked", receipt_reason: "approval_error", tool_calls: 0 });
    }, "Throwing approval hook blocks execution.");
    add("policy-revoked", seed, s => {
      s.host.remove_policy_rule = true;
      Object.assign(s, { status: "blocked", receipt_reason: "policy_changed", tool_calls: 0 });
    }, "Rule removed during approval blocks at policy recheck.");
    add("changed-metadata", seed, s => {
      s.proposal.arguments.metadata = { tracking: "added after digest" };
      s.host = { approval: "fixed", approval_digest_sha256: hash({ protocol: "aml-proposed-action/1",
        tool: seed.tool, effect: seed.effect, resource: seed.resource,
        purpose: `Challenge ${seed.id}`, arguments: copy(seed.arguments) }), tool: "return" };
      Object.assign(s, { status: "blocked", receipt_reason: "approval_missing_or_mismatched", tool_calls: 0 });
    }, "Adding a metadata field changes the digest and invalidates the old grant.");
  }
}

const mail = seeds[0];
const originalMail = { protocol: "aml-proposed-action/1", tool: mail.tool,
  effect: mail.effect, resource: mail.resource, purpose: "Challenge mail", arguments: copy(mail.arguments) };
add("injected-bcc-stale", mail, s => {
  s.proposal.arguments.bcc = ["unapproved@example.test"];
  s.host = { approval: "fixed", approval_digest_sha256: hash(originalMail), tool: "return" };
  Object.assign(s, { status: "blocked", receipt_reason: "approval_missing_or_mismatched", tool_calls: 0 });
}, "BCC injection after a grant changes the digest and blocks dispatch.");
add("injected-bcc-fresh", mail, s => {
  s.proposal.arguments.bcc = ["unapproved@example.test"];
}, "Counterexample: fresh approval of the changed proposal passes the generic boundary; a mail adapter must independently validate all recipients.");
add("caller-mutates-after-snapshot", mail, s => {
  s.host.mutate_proposal_body = "MUTATED";
}, "Caller and approval copy mutate while awaiting; frozen original is dispatched.");
const write = seeds.find(s => s.id === "write");
add("changed-call-id-stale", write, s => {
  s.proposal.arguments.functionCallId = "write-replayed-042";
  s.host = { approval: "fixed", approval_digest_sha256: hash({ protocol: "aml-proposed-action/1",
    tool: write.tool, effect: write.effect, resource: write.resource,
    purpose: "Challenge write", arguments: copy(write.arguments) }), tool: "return" };
  Object.assign(s, { status: "blocked", receipt_reason: "approval_missing_or_mismatched", tool_calls: 0 });
}, "A changed functionCallId mismatches the previous digest.");
add("exact-call-id-replay", write, undefined,
  "Counterexample: generic boundary alone does not reject an exact replay with a fresh approval; use a one-shot host claim.");
const http = seeds.find(s => s.id === "http");
add("argument-target-mismatch", http, s => {
  s.proposal.arguments.url = "https://other.example.test/v1/status";
}, "Counterexample: an allow rule on declared resource alone cannot validate the URL the HTTP tool uses; use a target resolver.");
add("numeric-object-keys", seeds.find(s => s.id === "read"), s => {
  s.proposal.arguments.index = { "12": "twelve", "2": "two", "01": "zero-one", a: "alpha" };
}, "Integer-looking keys follow JavaScript JSON property order in both implementations.");

const ids = new Set(rows.map(row => row.id));
assert.equal(ids.size, rows.length);
assert.ok(rows.length >= 50);
const cases = { protocol: "aml-action-expanded-challenge/1", existing_case_count: 13,
  project_authored: true, receipt_schema: "protocol/action-boundary-evidence-receipt.schema.json",
  cases: rows, claim_boundary: "Simulated host callbacks only. A hash detects changes to published fixture bytes; it does not authenticate a host, a human, an external effect, or arbitrary tool destinations." };
const receipts = rows.map(row => {
  const body = { protocol: "aml-action-boundary-evidence-receipt/1", case_id: row.id,
    provenance: "project-authored deterministic simulated-host fixture",
    proposal: row.proposal, host_policy: row.policy, host_fixture: row.host,
    expected_plan: row.expected.plan, expected_dispatch_receipt: row.expected.receipt,
    expected_tool_calls: row.expected.tool_calls,
    expected_executed_proposal: row.expected.executed_proposal,
    proposal_input_sha256: hash(row.proposal), initial_policy_sha256: hash(row.policy) };
  return { ...body, receipt_sha256: hash(body) };
});
const caseText = JSON.stringify(cases, null, 2) + "\n";
const receiptText = receipts.map(receipt => JSON.stringify(receipt)).join("\n") + "\n";
const mode = process.argv[2];
if (mode === "--write") {
  fs.writeFileSync(casesUrl, caseText);
  fs.writeFileSync(receiptsUrl, receiptText);
} else if (mode === "--check") {
  assert.equal(fs.readFileSync(casesUrl, "utf8"), caseText, "expanded challenge cases are stale");
  assert.equal(fs.readFileSync(receiptsUrl, "utf8"), receiptText, "expanded evidence receipts are stale");
} else if (mode !== undefined) throw new Error("Usage: node scripts/build-action-boundary-expanded.mjs [--write|--check]");
console.log(JSON.stringify({ cases: rows.length, receipts: receipts.length,
  case_file_sha256: crypto.createHash("sha256").update(caseText).digest("hex"),
  receipt_file_sha256: crypto.createHash("sha256").update(receiptText).digest("hex"),
  first_receipt_sha256: receipts[0].receipt_sha256 }));
