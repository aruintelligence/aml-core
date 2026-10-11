#!/usr/bin/env node
// Compare two project-authored function-tool adapters with simulated callbacks.
import assert from "node:assert/strict";
import fs from "node:fs";
import { createGuardedToolExecute } from "../pilots/action-boundary/guarded-tool.mjs";
import { createMailGuardedToolExecute } from "../pilots/action-boundary/mail-guarded-tool.mjs";
import { mailTargetResource } from "../pilots/action-boundary/mail-target-manifest.mjs";

const outputPath = new URL("../docs/mail-tool-report.json", import.meta.url);
const base = { to: "team@example.test", subject: "Release", body: "Ready." };
const specs = [
  { id: "aligned", title: "One intended destination", description: "Both adapters reach one local callback.", actual: base, intended: base, expected: [1, 1] },
  { id: "added_bcc", title: "The hidden second recipient", description: "A BCC addition reaches a To-only callback but lacks a complete-manifest policy rule.", actual: { ...base, bcc: ["outside@example.test"] }, intended: base, expected: [1, 0] },
  { id: "added_cc", title: "The visible second recipient", description: "A CC addition also changes the complete target.", actual: { ...base, cc: ["outside@example.test"] }, intended: base, expected: [1, 0] },
  { id: "approved_group", title: "An intended group", description: "A host rule for the complete group admits the same group in the callback.", actual: { ...base, cc: ["editor@example.test"], bcc: ["archive@example.test"] }, intended: { ...base, cc: ["editor@example.test"], bcc: ["archive@example.test"] }, expected: [1, 1] },
  { id: "unknown_field", title: "An unmodeled delivery field", description: "The strict adapter rejects an unknown argument before planning or callback.", actual: { ...base, recipients: ["outside@example.test"] }, intended: base, expected: [1, 0] },
  { id: "changed_body", title: "Same destination. New content.", description: "A recipient rule does not bind the body; both unreviewed fixtures still reach the callback.", actual: { ...base, body: "Changed text." }, intended: base, expected: [1, 1] },
  { id: "stale_approval", title: "Wrong approval digest", description: "Both approval-required paths reject a deliberately stale digest.", actual: base, intended: base, requiresApproval: true, stale: true, expected: [0, 0] }
];
const policy = (resource, required) => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource, requires_approval: required }
] });

async function run(spec, complete) {
  const callbacks = [];
  const intendedResource = complete ? mailTargetResource(spec.intended).resource : spec.intended.to;
  const options = { purpose: "Send release", policy: policy(intendedResource, !!spec.requiresApproval),
    execute: async args => { callbacks.push({ to: args.to, cc: args.cc ?? [], bcc: args.bcc ?? [] }); return { simulated: true }; },
    ...(spec.requiresApproval ? { requestApproval: async ({ proposal_sha256 }) =>
      ({ approved: true, proposal_sha256: spec.stale ? "0".repeat(64) : proposal_sha256 }) } : {}) };
  const tool = complete ? createMailGuardedToolExecute(options) : createGuardedToolExecute({
    ...options, tool: "send_message", effect: "send", resourceFor: args => args.to
  });
  try {
    const result = await tool(structuredClone(spec.actual));
    return { plan: result.plan, receipt: result.receipt, simulated_callbacks: callbacks.length,
      callback_destinations: callbacks };
  } catch (error) {
    assert.equal(callbacks.length, 0);
    return { mapping_error: error.message, simulated_callbacks: 0, callback_destinations: [] };
  }
}

const cases = [];
for (const spec of specs) {
  const to_only = await run(spec, false);
  const complete_mail = await run(spec, true);
  assert.deepEqual([to_only.simulated_callbacks, complete_mail.simulated_callbacks], spec.expected, spec.id);
  if (spec.id === "added_bcc" || spec.id === "added_cc") {
    assert.equal(to_only.receipt.execution_status, "dispatched");
    assert.equal(complete_mail.receipt.reason, "no_exact_rule");
  }
  if (spec.id === "unknown_field") assert.equal(complete_mail.mapping_error, "unsupported_mail_arguments");
  cases.push({ id: spec.id, title: spec.title, description: spec.description,
    intended_arguments: spec.intended, actual_arguments: spec.actual,
    intended_manifest: mailTargetResource(spec.intended).manifest,
    intended_resource: mailTargetResource(spec.intended).resource,
    to_only, complete_mail });
}
const report = { protocol: "aml-mail-tool-report/1",
  provenance: "Project-authored Node comparison. Both tool callbacks append only to memory; no mail service, real approval, or external effect is used.",
  distinction: "The To-only adapter can be correct for a To-only callback. This counterexample equips its callback with CC/BCC while leaving resourceFor on To. The new narrow adapter validates and binds all supported recipient roles.",
  caveat: "The complete adapter supports exactly to, cc, bcc, subject, and body. It cannot prove host policy ownership, authenticated approval, content acceptability, provider alias expansion, redirects, forwarding, or delivery.",
  cases };
const bytes = JSON.stringify(report, null, 2) + "\n";
if (process.argv.includes("--check")) {
  assert.equal(fs.readFileSync(outputPath, "utf8"), bytes, "Mail tool report is stale");
  console.log(`Verified ${cases.length} mail function-tool cases and report bytes`);
} else {
  fs.writeFileSync(outputPath, bytes);
  console.log(`Wrote ${cases.length} mail function-tool cases`);
}
