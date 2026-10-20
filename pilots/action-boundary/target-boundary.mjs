// Host-owned target binding for the proposed-action reference boundary.
// The resolver must derive the destination from the arguments the real tool
// will use. This module does not know a tool's schema or authenticate a user.
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { planAction, dispatchAction } from "./boundary.mjs";

function blocked(plan, reason) {
  return { plan, receipt: { protocol: "aml-action-dispatch/1",
    proposal_sha256: plan.proposal_sha256, policy_decision: plan.decision,
    execution_status: "blocked", reason } };
}

export async function dispatchTargetBoundAction(proposal, {
  policy, resolveTarget, requestApproval, consumeApproval, executeTool
} = {}) {
  // Snapshot before awaiting host code. The resolver receives its own copy,
  // and dispatchAction receives the original frozen snapshot.
  let frozen;
  try { frozen = JSON.parse(canonicalJSONStringify(proposal)); }
  catch {
    // The caller may have a changing getter or proxy. A second attempt could
    // bind this blocked receipt to different bytes than the failed snapshot.
    return blocked({ protocol: "aml-action-plan/1", proposal_sha256: null,
      decision: "deny", reason: "invalid_proposal" }, "invalid_proposal");
  }
  const plan = planAction(frozen, policy);
  if (plan.decision === "deny") return blocked(plan, plan.reason);
  if (typeof executeTool !== "function") return blocked(plan, "missing_host_dispatch");
  if (typeof resolveTarget !== "function") return blocked(plan, "target_resolver_unavailable");

  let actual;
  try {
    actual = await resolveTarget({ tool: frozen.tool, effect: frozen.effect,
      arguments: structuredClone(frozen.arguments) });
  } catch { return blocked(plan, "target_resolution_error"); }
  if (typeof actual !== "string" || !actual.trim()) return blocked(plan, "target_unavailable");
  if (actual !== frozen.resource) return blocked(plan, "target_mismatch");

  // The reference boundary rechecks host policy and digest-bound approval,
  // then passes its own frozen copy to the host callback.
  return dispatchAction(frozen, { policy, requestApproval, consumeApproval, executeTool });
}
