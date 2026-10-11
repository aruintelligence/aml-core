#!/usr/bin/env node
// Project-owned self-test adapter only. Outside witness credit requires an
// implementation maintained elsewhere that does not import boundary.mjs.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { planAction, dispatchAction } from "./boundary.mjs";

export async function runReferenceCase(input) {
  if (input.protocol !== "aml-action-challenge-case/1") throw new Error("Unknown case protocol");
  const proposal = structuredClone(input.proposal);
  const policy = structuredClone(input.policy);
  const plan = planAction(proposal, policy);
  let toolCalls = 0;
  let executedProposal = null;
  const host = input.host;
  const requestApproval = host.approval === "missing" ? undefined : async ({ proposal: copy, proposal_sha256 }) => {
    if (host.mutate_proposal_body) {
      proposal.arguments.body = host.mutate_proposal_body;
      copy.arguments.body = host.mutate_proposal_body;
    }
    if (host.remove_policy_rule) policy.rules.length = 0;
    if (host.approval === "throw") throw new Error("Simulated approval failure");
    return { approved: true, proposal_sha256:
      host.approval === "fixed" ? host.approval_digest_sha256 : proposal_sha256 };
  };
  const outcome = await dispatchAction(proposal, {
    policy,
    requestApproval,
    executeTool: async frozen => {
      toolCalls++;
      executedProposal = frozen;
      if (host.tool === "throw") throw new Error("Simulated callback uncertainty");
      return { simulated: true };
    }
  });
  return {
    protocol: "aml-action-boundary-result/1",
    plan,
    receipt: outcome.receipt,
    tool_calls: toolCalls,
    executed_proposal: executedProposal
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const file = process.argv[2];
  if (!file) {
    console.error("Usage: node challenge-reference-adapter.mjs <case.json>");
    process.exit(2);
  }
  console.log(JSON.stringify(await runReferenceCase(JSON.parse(fs.readFileSync(file, "utf8")))));
}
