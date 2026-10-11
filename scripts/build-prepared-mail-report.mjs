#!/usr/bin/env node
// Reproduce a host transformation on either side of the mail policy boundary.
import assert from "node:assert/strict";
import fs from "node:fs";
import { planAction } from "../pilots/action-boundary/boundary.mjs";
import { createMailGuardedToolExecute } from "../pilots/action-boundary/mail-guarded-tool.mjs";
import { createPreparedMailToolExecute } from "../pilots/action-boundary/prepared-mail-tool.mjs";
import { mailTargetResource } from "../pilots/action-boundary/mail-target-manifest.mjs";

const outputPath = new URL("../docs/prepared-mail-report.json", import.meta.url);
const source = { to: "team@example.test", subject: "Release", body: "Ready." };
const specs = [
  { id: "aligned", title: "No transformation", description: "Both paths submit the same intended request to one in-memory provider callback.", route: {}, expected: [1, 1] },
  { id: "route_bcc", title: "Routing adds a hidden recipient", description: "The post-gate transformation adds a BCC after the old check. Preparing it first reveals the new destination to policy.", route: { bcc: ["outside@example.test"] }, expected: [1, 0] },
  { id: "route_cc", title: "Routing adds a visible recipient", description: "The same issue applies when a host routing rule adds CC.", route: { cc: ["outside@example.test"] }, expected: [1, 0] },
  { id: "approved_group", title: "A group the host intended", description: "A rule for the complete prepared request permits the intended group. The old path checks only the unexpanded input and cannot match that rule.", route: { cc: ["editor@example.test"] }, intendedRoute: { cc: ["editor@example.test"] }, expected: [0, 1] },
  { id: "changed_body", title: "Changed text after input approval", description: "A fixed simulated approval for the original body lets the old post-gate change reach its callback. The prepared path presents the changed text and rejects that stale digest.", route: { body: "Changed after input." }, requiresApproval: true, approval: "original", expected: [1, 0] },
  { id: "unknown_field", title: "An unmodeled delivery field", description: "The prepared request rejects a field outside the five-field schema before the provider callback.", route: { recipients: ["outside@example.test"] }, expected: [1, 0] },
  { id: "stale_approval", title: "Wrong approval digest", description: "A deliberately wrong digest blocks both paths before a callback.", route: {}, requiresApproval: true, approval: "wrong", expected: [0, 0] },
  { id: "provider_error", title: "Provider callback throws", description: "A callback error stays unknown on both paths. Neither adapter retries automatically.", route: {}, providerError: true, expected: [1, 1] }
];

const prepare = (args, route) => ({ ...args, ...structuredClone(route) });
const policyFor = (args, requiresApproval) => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: mailTargetResource(args).resource,
    requires_approval: requiresApproval }
] });
const proposalFor = args => ({ protocol: "aml-proposed-action/1", tool: "send_message",
  effect: "send", resource: mailTargetResource(args).resource,
  purpose: "Send release", arguments: args });

async function run(spec, beforePolicy) {
  const sent = [];
  const intended = prepare(source, spec.intendedRoute ?? {});
  const policy = policyFor(intended, !!spec.requiresApproval);
  const originalDigest = planAction(proposalFor(source), policyFor(source, true)).proposal_sha256;
  const options = { purpose: "Send release", policy,
    ...(spec.requiresApproval ? { requestApproval: async () => ({ approved: true,
      proposal_sha256: spec.approval === "wrong" ? "0".repeat(64) : originalDigest }) } : {}) };
  const simulate = request => {
    sent.push({ to: request.to, cc: request.cc ?? [], bcc: request.bcc ?? [],
      subject: request.subject, body: request.body,
      ...(Object.hasOwn(request, "recipients") ? { recipients: request.recipients } : {}) });
    if (spec.providerError) throw new Error("transport_uncertain");
    return { simulated: true };
  };
  const tool = beforePolicy ? createPreparedMailToolExecute({ ...options,
    prepare: args => prepare(args, spec.route), execute: simulate }) :
    createMailGuardedToolExecute({ ...options,
      execute: args => simulate(prepare(args, spec.route)) });
  try {
    const result = await tool(structuredClone(source));
    return { plan: result.plan, receipt: result.receipt,
      simulated_provider_callbacks: sent.length, submitted_requests: sent };
  } catch (error) {
    assert.equal(sent.length, 0);
    return { preparation_error: error.message,
      simulated_provider_callbacks: 0, submitted_requests: [] };
  }
}

const cases = [];
for (const spec of specs) {
  const post_gate = await run(spec, false);
  const prepared_first = await run(spec, true);
  assert.deepEqual([post_gate.simulated_provider_callbacks,
    prepared_first.simulated_provider_callbacks], spec.expected, spec.id);
  if (["route_bcc", "route_cc"].includes(spec.id)) {
    assert.equal(post_gate.receipt.execution_status, "dispatched");
    assert.equal(prepared_first.receipt.reason, "no_exact_rule");
  }
  if (spec.id === "changed_body") {
    assert.equal(post_gate.submitted_requests[0].body, "Changed after input.");
    assert.equal(prepared_first.receipt.reason, "approval_missing_or_mismatched");
  }
  if (spec.id === "unknown_field") assert.equal(prepared_first.preparation_error, "unsupported_mail_arguments");
  if (spec.id === "provider_error") {
    assert.equal(post_gate.receipt.execution_status, "unknown");
    assert.equal(prepared_first.receipt.execution_status, "unknown");
  }
  cases.push({ id: spec.id, title: spec.title, description: spec.description,
    tool_input: source, intended_request: prepare(source, spec.intendedRoute ?? {}),
    transformed_request: prepare(source, spec.route),
    post_gate, prepared_first });
}
const report = { protocol: "aml-prepared-mail-report/1",
  provenance: "Project-authored Node execution with in-memory provider callbacks. No mail service, authenticated approval, or external effect.",
  distinction: "The earlier complete-recipient adapter checks the tool input. If a host callback builds a different provider request after that check, the request is outside that earlier decision. The opt-in prepared adapter builds and validates the narrow provider request before policy and any approval.",
  caveat: "The host sender must submit precisely the prepared fields and cannot silently append another delivery route. This adapter does not validate provider aliases, list expansion, forwarding, actual delivery, content safety, policy ownership, or human consent.",
  cases };
const bytes = JSON.stringify(report, null, 2) + "\n";
if (process.argv.includes("--check")) {
  assert.equal(fs.readFileSync(outputPath, "utf8"), bytes, "Prepared mail report is stale");
  console.log(`Verified ${cases.length} prepared mail cases and report bytes`);
} else {
  fs.writeFileSync(outputPath, bytes);
  console.log(`Wrote ${cases.length} prepared mail cases`);
}
