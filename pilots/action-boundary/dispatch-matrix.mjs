#!/usr/bin/env node
// Exhaustive only over the finite axes below. Host-owned local callbacks; no
// person, provider, network request, or external effect is involved.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dispatchAction } from "./boundary.mjs";

const reportUrl = new URL("../../docs/action-dispatch-matrix.json", import.meta.url);
export const axes = Object.freeze({
  policy: ["deny", "allow", "requires_approval", "ambiguous"],
  approval: ["match", "decline", "mismatch", "throw", "revoke", "mutate_caller"],
  claim: ["accept", "refuse", "throw_after_consume", "revoke_after_consume"],
  callback: ["return", "throw_after_write"]
});

async function runVector(policyMode, approvalMode, claimMode, callbackMode) {
  const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
    resource: "team@example.test", purpose: "Matrix local callback",
    arguments: { to: "team@example.test", body: "Build passed." } };
  const rule = { tool: proposal.tool, effect: proposal.effect, resource: proposal.resource,
    requires_approval: policyMode === "requires_approval" };
  const policy = { protocol: "aml-action-policy/1",
    rules: policyMode === "deny" ? [] : policyMode === "ambiguous" ? [rule, { ...rule }] : [rule] };
  let approvalRequests = 0;
  let claimAttempts = 0;
  let claimsConsumed = 0;
  let callbackCount = 0;
  let fixtureWrites = 0;
  let callbackTarget = null;
  const outcome = await dispatchAction(proposal, { policy,
    requestApproval: async ({ proposal: offered, proposal_sha256 }) => {
      approvalRequests++;
      if (approvalMode === "throw") throw new Error("local_approval_error");
      if (approvalMode === "revoke") policy.rules = [];
      if (approvalMode === "mutate_caller") {
        proposal.arguments.to = "other@example.test";
        offered.arguments.to = "other@example.test";
      }
      if (approvalMode === "decline") return { approved: false };
      return { approved: true,
        proposal_sha256: approvalMode === "mismatch" ? "0".repeat(64) : proposal_sha256 };
    },
    consumeApproval: async () => {
      claimAttempts++;
      if (claimMode === "refuse") return false;
      claimsConsumed++;
      if (claimMode === "throw_after_consume") throw new Error("local_claim_error");
      if (claimMode === "revoke_after_consume") policy.rules = [];
      return true;
    },
    executeTool: async frozen => {
      callbackCount++;
      callbackTarget = frozen.arguments.to;
      if (callbackMode === "throw_after_write") {
        fixtureWrites++;
        throw new Error("local_callback_error_after_write");
      }
      return { would_send_to: frozen.arguments.to };
    }
  });
  return { policy: policyMode, approval: approvalMode, claim: claimMode, callback: callbackMode,
    receipt: outcome.receipt, approval_requests: approvalRequests, claim_attempts: claimAttempts,
    claims_consumed: claimsConsumed, callback_count: callbackCount, fixture_writes: fixtureWrites,
    callback_target: callbackTarget, caller_target_after: proposal.arguments.to,
    result_target: outcome.result?.would_send_to ?? null };
}

export async function buildDispatchMatrix() {
  const rows = [];
  for (const policy of axes.policy) for (const approval of axes.approval)
    for (const claim of axes.claim) for (const callback of axes.callback)
      rows.push(await runVector(policy, approval, claim, callback));
  return { protocol: "aml-action-dispatch-matrix/1",
    provenance: "project-authored bounded cross-product of local callbacks",
    limits: "192 finite combinations. No human approval, provider call, delivery, arbitrary interleaving, or production safety proof.",
    axes, rows };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (!(args.length === 0 || (args.length === 1 && ["--write", "--check"].includes(args[0])))) {
    throw new Error("Use no argument, --write, or --check");
  }
  const report = await buildDispatchMatrix();
  const json = JSON.stringify(report, null, 2) + "\n";
  if (args[0] === "--write") {
    await writeFile(reportUrl, json, "utf8");
    console.log(`Wrote ${report.rows.length} local dispatch vectors.`);
  } else if (args[0] === "--check") {
    assert.equal(await readFile(reportUrl, "utf8"), json, "Dispatch matrix is stale; run --write");
    console.log(`${report.rows.length} local dispatch vectors match the checked-in matrix.`);
  } else process.stdout.write(json);
}
