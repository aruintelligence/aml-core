#!/usr/bin/env node
// Simulates a to-only resolver against a complete mail-recipient manifest.
import assert from "node:assert/strict";
import fs from "node:fs";
import { dispatchTargetBoundAction } from "../pilots/action-boundary/target-boundary.mjs";
import { mailTargetResource, resolveMailTarget } from "../pilots/action-boundary/mail-target-manifest.mjs";

const outputPath = new URL("../docs/mail-target-report.json", import.meta.url);
const base = { to: "team@example.test", subject: "Release", body: "The release is ready." };
const specs = [
  { id: "aligned", title: "One intended recipient", description: "The approved and actual manifests agree.",
    args: { ...base }, approved: { ...base }, expected: [1, 1, "host_dispatch_returned"] },
  { id: "hidden_bcc", title: "One visible. Two actual.", description: "The To field remains approved; a new BCC address reaches the to-only callback.",
    args: { ...base, bcc: ["outside@example.test"] }, approved: { ...base }, expected: [1, 0, "target_mismatch"] },
  { id: "added_cc", title: "A second recipient in CC", description: "A CC addition is also absent from a to-only resource.",
    args: { ...base, cc: ["outside@example.test"] }, approved: { ...base }, expected: [1, 0, "target_mismatch"] },
  { id: "authorized_multi", title: "Multiple recipients can be intentional", description: "When the host policy names the whole recipient manifest, both destinations are admitted in this local fixture.",
    args: { ...base, cc: ["editor@example.test"], bcc: ["archive@example.test"] },
    approved: { ...base, cc: ["editor@example.test"], bcc: ["archive@example.test"] }, expected: [1, 1, "host_dispatch_returned"] },
  { id: "unknown_field", title: "Unknown delivery field", description: "An unsupported recipients field fails the strict schema before the callback.",
    args: { ...base, recipients: ["outside@example.test"] }, approved: { ...base }, expected: [1, 0, "target_resolution_error"] },
  { id: "malformed_bcc", title: "Malformed BCC field", description: "A null BCC is not silently treated as an empty destination list.",
    args: { ...base, bcc: null }, approved: { ...base }, expected: [1, 0, "target_resolution_error"] },
  { id: "changed_body", title: "Same recipients, changed content", description: "The manifest covers destinations, not message content; the unreviewed rule still permits a changed body.",
    args: { ...base, body: "Different release text." }, approved: { ...base }, expected: [1, 1, "host_dispatch_returned"] }
];
const proposal = (args, resource) => ({ protocol: "aml-proposed-action/1", tool: "send_message",
  effect: "send", resource, purpose: "Send a release update", arguments: args });
const policy = resource => ({ protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource, requires_approval: false }
] });

async function run(args, resource, resolver) {
  const callbacks = [];
  const result = await dispatchTargetBoundAction(proposal(args, resource), {
    policy: policy(resource), resolveTarget: resolver,
    executeTool: async frozen => { callbacks.push({
      to: frozen.arguments.to ?? null, cc: frozen.arguments.cc ?? null,
      bcc: frozen.arguments.bcc ?? null }); return { simulated: true }; }
  });
  return { receipt: result.receipt, simulated_callbacks: callbacks.length, callback_destinations: callbacks };
}

const cases = [];
for (const spec of specs) {
  const approved = mailTargetResource(spec.approved);
  let actual = null;
  try { actual = mailTargetResource(spec.args); } catch { /* Unsupported argument shape is reported by the resolver. */ }
  const primary_only = await run(spec.args, spec.approved.to,
    ({ tool, effect, arguments: args }) => {
      if (tool !== "send_message" || effect !== "send") throw Error("unsupported tool");
      return args.to;
    });
  const full_manifest = await run(spec.args, approved.resource, resolveMailTarget);
  assert.equal(primary_only.simulated_callbacks, spec.expected[0], `${spec.id}: to-only callback`);
  assert.equal(full_manifest.simulated_callbacks, spec.expected[1], `${spec.id}: complete callback`);
  assert.equal(full_manifest.receipt.reason, spec.expected[2], `${spec.id}: complete receipt`);
  cases.push({ id: spec.id, title: spec.title, description: spec.description,
    input_arguments: spec.args, approved_manifest: approved.manifest,
    actual_manifest: actual?.manifest ?? null,
    approved_resource: approved.resource, actual_resource: actual?.resource ?? null,
    primary_only, full_manifest });
}
const report = { protocol: "aml-mail-target-report/1",
  provenance: "Project-authored local Node simulation; both paths use the same target-bound action wrapper with different host mappers and policies. Callbacks append only to memory.",
  manifest_contract: "The supported mail tool uses exactly to, cc, bcc, subject, and body. Destination roles and ordered addresses become a canonical JSON manifest. Its SHA-256 is an exact policy resource key, not an approval.",
  caveat: "The example assumes the actual mail callback uses exactly these destination fields and rejects other delivery routes. A different API, redirects, aliases, or downstream rewriting needs its own mapper. Message content and human authorization require separate checks. No message was sent.",
  cases };
const bytes = JSON.stringify(report, null, 2) + "\n";
if (process.argv.includes("--check")) {
  assert.equal(fs.readFileSync(outputPath, "utf8"), bytes, "Mail target report is stale");
  console.log(`Verified ${cases.length} complete-recipient scenarios and report bytes`);
} else {
  fs.writeFileSync(outputPath, bytes);
  console.log(`Wrote ${cases.length} scenarios to ${outputPath.pathname}`);
}
