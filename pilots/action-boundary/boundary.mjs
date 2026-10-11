// Reference boundary for host-owned tool dispatch. This module does not authenticate
// a person, confer tool permissions, or prove that an external side effect completed.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

export const PROTOCOL = "aml-proposed-action/1";
const EFFECTS = new Set(["read", "write", "send", "pay", "delete"]);
const hex = value => crypto.createHash("sha256").update(value, "utf8").digest("hex");
const plain = value => value && typeof value === "object" && !Array.isArray(value);
const keysAre = (value, keys) => Object.keys(value).sort().join("|") === [...keys].sort().join("|");

function snapshot(proposal) {
  if (!plain(proposal) || !keysAre(proposal, ["protocol", "tool", "effect", "resource", "purpose", "arguments"]) ||
      proposal.protocol !== PROTOCOL || !["tool", "resource", "purpose"].every(k =>
        typeof proposal[k] === "string" && proposal[k].trim() && proposal[k].length <= 256) ||
      !EFFECTS.has(proposal.effect) || !plain(proposal.arguments)) {
    throw new Error("invalid_proposal");
  }
  const bytes = canonicalJSONStringify(proposal);
  if (Buffer.byteLength(bytes, "utf8") > 65536) throw new Error("proposal_too_large");
  return { bytes, digest: hex(bytes), value: JSON.parse(bytes) };
}

function ruleFor(proposal, policy) {
  if (!plain(policy) || policy.protocol !== "aml-action-policy/1" || !Array.isArray(policy.rules)) {
    throw new Error("invalid_policy");
  }
  for (const rule of policy.rules) {
    if (!plain(rule) || !keysAre(rule, ["tool", "effect", "resource", "requires_approval"]) ||
        !["tool", "resource"].every(k => typeof rule[k] === "string" && rule[k].trim()) ||
        !EFFECTS.has(rule.effect) || typeof rule.requires_approval !== "boolean") {
      throw new Error("invalid_policy");
    }
  }
  const matching = policy.rules.filter(rule => rule.tool === proposal.tool &&
    rule.effect === proposal.effect && rule.resource === proposal.resource);
  if (matching.length > 1) throw new Error("ambiguous_policy");
  return matching[0];
}

export function planAction(proposal, policy) {
  try {
    const frozen = snapshot(proposal);
    const rule = ruleFor(frozen.value, policy);
    return { protocol: "aml-action-plan/1", proposal_sha256: frozen.digest,
      decision: !rule ? "deny" : rule.requires_approval ? "requires_approval" : "allow",
      reason: rule ? "exact_rule" : "no_exact_rule" };
  } catch (error) {
    return { protocol: "aml-action-plan/1", proposal_sha256: null,
      decision: "deny", reason: error.message };
  }
}

// requestApproval and executeTool must be supplied by the trusted host. A model
// must never supply either callback or the policy. No approval callback => deny.
export async function dispatchAction(proposal, { policy, requestApproval, executeTool } = {}) {
  const plan = planAction(proposal, policy);
  const receipt = (status, reason) => ({ protocol: "aml-action-dispatch/1",
    proposal_sha256: plan.proposal_sha256, policy_decision: plan.decision,
    execution_status: status, reason });
  if (plan.decision === "deny") return { receipt: receipt("blocked", plan.reason) };
  if (typeof executeTool !== "function") return { receipt: receipt("blocked", "missing_host_dispatch") };
  const frozen = snapshot(proposal);
  if (plan.decision === "requires_approval") {
    if (typeof requestApproval !== "function") return { receipt: receipt("blocked", "approval_unavailable") };
    let approval;
    try { approval = await requestApproval({ proposal: JSON.parse(frozen.bytes), proposal_sha256: frozen.digest }); }
    catch { return { receipt: receipt("blocked", "approval_error") }; }
    if (approval?.approved !== true || approval?.proposal_sha256 !== frozen.digest) {
      return { receipt: receipt("blocked", "approval_missing_or_mismatched") };
    }
  }
  // Re-read host policy after an asynchronous approval. Dispatch the frozen
  // proposal, never the mutable original or a callback-modified copy.
  const rechecked = planAction(frozen.value, policy);
  if (rechecked.decision !== plan.decision || rechecked.proposal_sha256 !== frozen.digest) {
    return { receipt: receipt("blocked", "policy_changed") };
  }
  try {
    const result = await executeTool(JSON.parse(frozen.bytes));
    return { receipt: receipt("dispatched", "host_dispatch_returned"), result };
  } catch {
    // A thrown transport can follow a partial side effect. Never claim it did
    // not occur, and never retry automatically.
    return { receipt: receipt("unknown", "host_dispatch_error") };
  }
}
