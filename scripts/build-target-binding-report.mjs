#!/usr/bin/env node
// Executable local comparison. Callbacks only append to in-memory arrays.
import assert from "node:assert/strict";
import fs from "node:fs";
import { planAction, dispatchAction } from "../pilots/action-boundary/boundary.mjs";
import { dispatchTargetBoundAction } from "../pilots/action-boundary/target-boundary.mjs";

const outputPath = new URL("../docs/target-binding-report.json", import.meta.url);
const base = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
  resource: "team@example.test", purpose: "Send the release update",
  arguments: { to: "team@example.test", body: "The release is ready." } };
const clone = () => structuredClone(base);
const recipient = ({ tool, effect, arguments: args }) => {
  if (tool !== "send_message" || effect !== "send") throw Error("unsupported tool");
  return args.to;
};
const specs = [
  { id: "aligned", title: "Declared and actual target agree", description: "Control: the rule, resource, and recipient match.",
    proposal: clone(), expected: [1, 1, "host_dispatch_returned"] },
  { id: "forged_recipient", title: "Same rule. Different recipient.",
    description: "The declared resource stays approved, while arguments.to points outside.",
    proposal: { ...clone(), arguments: { ...base.arguments, to: "outside@example.test" } },
    expected: [1, 0, "target_mismatch"] },
  { id: "fresh_digest", title: "A fresh digest still needs a target check",
    description: "A project-authored approval fixture accepts this exact changed digest. It is not human consent; binding still rejects the recipient mismatch.",
    approval: true, proposal: { ...clone(), arguments: { ...base.arguments, to: "outside@example.test" } },
    expected: [1, 0, "target_mismatch"] },
  { id: "missing_recipient", title: "The recipient is missing",
    description: "A permissive rule alone reaches the simulated callback with no to argument; the resolver fails closed.",
    proposal: { ...clone(), arguments: { body: base.arguments.body } },
    expected: [1, 0, "target_unavailable"] },
  { id: "resolver_error", title: "The host mapper fails",
    description: "A thrown target resolver stops the bound path before approval or callback.",
    proposal: clone(), resolverError: true, expected: [1, 0, "target_resolution_error"] },
  { id: "changed_body", title: "Target binding is not content approval",
    description: "The recipient is aligned, while the body changes. Both unreviewed paths reach the simulated callback.",
    proposal: { ...clone(), arguments: { ...base.arguments, body: "Different release text." } },
    expected: [1, 1, "host_dispatch_returned"] },
  { id: "changed_resource", title: "The rule rejects a declared route change",
    description: "Changing the resource itself misses the exact rule before the target resolver runs.",
    proposal: { ...clone(), resource: "outside@example.test", arguments: { ...base.arguments, to: "outside@example.test" } },
    expected: [0, 0, "no_exact_rule"] }
];
const policy = approval => ({ protocol: "aml-action-policy/1", rules: [
  { tool: base.tool, effect: base.effect, resource: base.resource, requires_approval: approval }
] });

async function run(spec, bound) {
  const calls = [], mapped = [];
  const chosenPolicy = policy(!!spec.approval);
  const plan = planAction(spec.proposal, chosenPolicy);
  const host = { policy: chosenPolicy,
    requestApproval: spec.approval ? async ({ proposal_sha256 }) =>
      ({ approved: true, proposal_sha256, fixture: "project-authored exact-digest response" }) : undefined,
    executeTool: async frozen => { calls.push(frozen.arguments.to ?? null); return { simulated: true }; } };
  if (bound) host.resolveTarget = input => {
    if (spec.resolverError) throw Error("simulated host mapper outage");
    const value = recipient(input); mapped.push(value ?? null); return value;
  };
  const result = bound ? await dispatchTargetBoundAction(spec.proposal, host) :
    await dispatchAction(spec.proposal, host);
  return { plan, receipt: result.receipt, simulated_callbacks: calls.length,
    simulated_callback_targets: calls, mapped_targets: mapped };
}

const cases = [];
for (const spec of specs) {
  const reference = await run(spec, false), target_bound = await run(spec, true);
  assert.equal(reference.simulated_callbacks, spec.expected[0], `${spec.id}: reference callback`);
  assert.equal(target_bound.simulated_callbacks, spec.expected[1], `${spec.id}: bound callback`);
  assert.equal(target_bound.receipt.reason, spec.expected[2], `${spec.id}: bound reason`);
  assert.equal(reference.plan.proposal_sha256, target_bound.plan.proposal_sha256, `${spec.id}: digest`);
  cases.push({ id: spec.id, title: spec.title, description: spec.description,
    declared_resource: spec.proposal.resource, argument_to: spec.proposal.arguments.to ?? null,
    body: spec.proposal.arguments.body, digest_fixture_only: !!spec.approval,
    reference, target_bound });
}
const report = { protocol: "aml-target-binding-report/1",
  provenance: "Project-authored local Node simulation. Both paths call the same action-boundary reference; the bound path adds a host-owned resolver. Callbacks append to memory only.",
  binding: "The host derives the actual recipient from frozen arguments and requires exact equality with the proposal resource before approval or callback.",
  caveat: "A trustworthy, tool-specific host mapper is essential. This example does not authenticate a person, validate message content, prove delivery, or guarantee a downstream tool uses the mapped field. The baseline is intentionally permissive and no real message is sent.",
  cases };
const bytes = JSON.stringify(report, null, 2) + "\n";
if (process.argv.includes("--check")) {
  assert.equal(fs.readFileSync(outputPath, "utf8"), bytes, "Target-binding report is stale");
  console.log(`Verified ${cases.length} target-binding scenarios and report bytes`);
} else {
  fs.writeFileSync(outputPath, bytes);
  console.log(`Wrote ${cases.length} scenarios to ${outputPath.pathname}`);
}
