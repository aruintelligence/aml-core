import assert from "node:assert/strict";
import fs from "node:fs";
import { planAction, dispatchAction } from "../pilots/action-boundary/boundary.mjs";

const outputPath = new URL("../docs/action-policy-scope-report.json", import.meta.url);
const base = {
  protocol: "aml-proposed-action/1",
  tool: "send_message", effect: "send", resource: "team@example.test",
  purpose: "Send the release update",
  arguments: { to: "team@example.test", body: "The release is ready." }
};
const clone = () => structuredClone(base);
const variants = [
  { id: "original", title: "Approved release text", description: "The exact original proposal.",
    proposal: clone(), unreviewedCalls: 1, reviewedCalls: 1 },
  { id: "changed_body", title: "Same address, different message",
    description: "The destination stays the same while the message body changes.",
    proposal: { ...clone(), arguments: { ...base.arguments, body: "Send the unreleased draft instead." } },
    unreviewedCalls: 1, reviewedCalls: 0 },
  { id: "changed_purpose", title: "Same address, different purpose",
    description: "The declared purpose changes, but the rule's matching tuple does not.",
    proposal: { ...clone(), purpose: "Request an unpublished draft" },
    unreviewedCalls: 1, reviewedCalls: 0 },
  { id: "extra_argument", title: "Same address, extra argument",
    description: "A new argument changes the proposal digest, not the rule match.",
    proposal: { ...clone(), arguments: { ...base.arguments, cc: "archive@example.test" } },
    unreviewedCalls: 1, reviewedCalls: 0 },
  { id: "changed_destination", title: "Different destination",
    description: "The host-mapped resource and the recipient both change.",
    proposal: { ...clone(), resource: "outside@example.test",
      arguments: { ...base.arguments, to: "outside@example.test" } },
    unreviewedCalls: 0, reviewedCalls: 0 },
  { id: "changed_effect", title: "Different effect",
    description: "The declared effect changes from send to pay.",
    proposal: { ...clone(), effect: "pay" },
    unreviewedCalls: 0, reviewedCalls: 0 },
  { id: "changed_tool", title: "Different tool",
    description: "The requested tool changes under the same destination.",
    proposal: { ...clone(), tool: "post_update" },
    unreviewedCalls: 0, reviewedCalls: 0 },
  { id: "reordered_keys", title: "Keys reordered, meaning unchanged",
    description: "Only object member order changes; canonical JSON retains the original digest.",
    proposal: { arguments: { body: base.arguments.body, to: base.arguments.to },
      purpose: base.purpose, resource: base.resource, effect: base.effect,
      tool: base.tool, protocol: base.protocol },
    unreviewedCalls: 1, reviewedCalls: 1 }
];
const policy = requires_approval => ({ protocol: "aml-action-policy/1", rules: [
  { tool: base.tool, effect: base.effect, resource: base.resource, requires_approval }
] });
const originalDigest = planAction(base, policy(true)).proposal_sha256;
assert.match(originalDigest, /^[a-f0-9]{64}$/);

async function run(proposal, requiresApproval) {
  let callbacks = 0;
  let executed = null;
  const selectedPolicy = policy(requiresApproval);
  const plan = planAction(proposal, selectedPolicy);
  const result = await dispatchAction(proposal, {
    policy: selectedPolicy,
    // A fixed host fixture reuses the digest of the original proposal. This is
    // not a person approving anything and cannot authorize the changed payload.
    requestApproval: requiresApproval ? async () =>
      ({ approved: true, proposal_sha256: originalDigest }) : undefined,
    executeTool: async frozen => { callbacks++; executed = frozen; return { simulated: true }; }
  });
  return { plan, receipt: result.receipt, simulated_callbacks: callbacks,
    executed_proposal: executed };
}

const cases = [];
for (const spec of variants) {
  const unreviewed = await run(spec.proposal, false);
  const reviewed = await run(spec.proposal, true);
  assert.equal(unreviewed.simulated_callbacks, spec.unreviewedCalls, spec.id);
  assert.equal(reviewed.simulated_callbacks, spec.reviewedCalls, spec.id);
  assert.equal(unreviewed.plan.proposal_sha256, reviewed.plan.proposal_sha256, spec.id);
  assert.equal(unreviewed.plan.proposal_sha256 === originalDigest,
    spec.id === "original" || spec.id === "reordered_keys", spec.id);
  if (spec.unreviewedCalls === 1) assert.equal(unreviewed.receipt.execution_status, "dispatched", spec.id);
  if (spec.reviewedCalls === 0) assert.equal(reviewed.receipt.execution_status, "blocked", spec.id);
  cases.push({ id: spec.id, title: spec.title, description: spec.description,
    proposal: spec.proposal, digest_matches_original: unreviewed.plan.proposal_sha256 === originalDigest,
    unreviewed, digest_bound_host_decision: reviewed });
}

const report = {
  protocol: "aml-action-policy-scope-report/1",
  evidence: "Project-authored local simulation; the reference dispatchAction ran with a simulated callback. No message, person, MCP host, or external service was involved.",
  original_proposal_sha256: originalDigest,
  policy_match_fields: ["tool", "effect", "resource"],
  approval_binding: "The second policy requires approval; the host fixture returns only the original proposal digest. It is not human authorization.",
  caveat: "A changed argument can still match a rule without approval. Digest-bound approval blocks a stale digest, but only a trusted host can decide whether to authorize a new digest. Hosts must map the true resource and enforce any content-specific restrictions themselves.",
  cases
};
const serialized = JSON.stringify(report, null, 2) + "\n";
if (process.argv.includes("--check")) {
  assert.equal(fs.readFileSync(outputPath, "utf8"), serialized,
    "Policy scope report is stale; regenerate with node scripts/build-action-policy-scope-report.mjs");
  process.stdout.write(`Policy scope report matches ${cases.length} executable cases\n`);
} else {
  fs.writeFileSync(outputPath, serialized);
  process.stdout.write(`Wrote ${cases.length} policy scope cases to ${outputPath.pathname}\n`);
}
