// Opt-in host adapter joining the prepared mail boundary to the file-backed
// authority. Host callbacks own preparation, policy, human authentication,
// revocation, and the actual provider handoff. This sends nothing by itself.
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { planAction } from "./boundary.mjs";
import { validHandoffIdentity } from "./handoff-binding.mjs";
import { mailTargetResource } from "./mail-target-manifest.mjs";

const snapshot = value => JSON.parse(canonicalJSONStringify(value));

export function createRevocablePreparedMailToolExecute({ authority, tenant, issuer,
  actor, audience, purpose, operationIdFor, getPolicy, prepare, requestApproval, execute,
  ttlMs = 60_000 } = {}) {
  if (![tenant, issuer, actor, audience, purpose].every(validHandoffIdentity) ||
      typeof operationIdFor !== "function" || typeof getPolicy !== "function" ||
      typeof prepare !== "function" ||
      typeof requestApproval !== "function" || typeof execute !== "function" ||
      !authority || typeof authority.observeIssuer !== "function" ||
      typeof authority.issue !== "function" ||
      typeof authority.dispatch !== "function" ||
      !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 300_000) {
    throw new TypeError("Trusted host identity, authority, policy, approval, and callbacks are required");
  }

  const identity = Object.freeze({ tenant, issuer, actor, audience, tool: "send_message" });
  return async function revocablePreparedMailExecute(args, context) {
    // Host operation identity must survive process retries. Never derive it
    // from the model's request or from its proposal digest.
    const operationId = operationIdFor(context);
    if (!validHandoffIdentity(operationId)) throw new TypeError("invalid_host_operation_id");
    // Validate the untrusted input before preparation, then bind the complete
    // provider request (including BCC and content) after host preparation.
    const source = snapshot(args);
    mailTargetResource(source);
    const prepared = snapshot(await prepare(structuredClone(source), context));
    const resource = mailTargetResource(prepared).resource;
    const proposal = { protocol: "aml-proposed-action/1", tool: "send_message",
      effect: "send", resource, purpose, arguments: prepared };
    const policy = snapshot(getPolicy());
    const policyBytes = canonicalJSONStringify(policy);
    const plan = planAction(proposal, policy);
    const receipt = (execution_status, reason) => ({ protocol: "aml-action-dispatch/1",
      proposal_sha256: plan.proposal_sha256, policy_decision: plan.decision,
      execution_status, reason });
    const blocked = reason => ({ protocol: "aml-revocable-prepared-mail-result/1",
      plan, receipt: receipt("blocked", reason), dispatch_count: 0 });
    if (plan.decision !== "requires_approval") {
      return blocked(plan.decision === "deny" ? plan.reason : "approval_required_rule");
    }

    let observed;
    try {
      // Observe before awaiting the human. No grant exists until approval.
      observed = authority.observeIssuer(identity);
      if (!Number.isSafeInteger(observed?.epoch) || observed.epoch < 0) {
        return blocked("authority_observation_unavailable");
      }
    } catch { return blocked("authority_observation_unavailable"); }

    let approval;
    try {
      approval = await requestApproval({ proposal: snapshot(proposal),
        proposal_sha256: plan.proposal_sha256 }, context);
    } catch { return blocked("approval_error"); }
    if (approval?.approved !== true || approval?.proposal_sha256 !== plan.proposal_sha256) {
      return blocked("approval_missing_or_mismatched");
    }
    try {
      if (canonicalJSONStringify(getPolicy()) !== policyBytes) return blocked("policy_changed");
    } catch { return blocked("policy_unavailable"); }

    const binding = { ...identity, policy, preparedRequest: prepared };
    let grant;
    try {
      // Conditional issuance checks the SAME epoch observed before approval.
      // Revocation during the wait blocks even if a new grant could otherwise
      // be issued at the newer epoch.
      grant = authority.issue(binding, { ttlMs, expectedEpoch: observed.epoch, operationId });
    } catch (error) {
      const reason = ["issuer_revoked", "operation_already_claimed", "operation_payload_mismatch"]
        .includes(error?.message) ? error.message : "authority_issue_unavailable";
      return blocked(reason);
    }

    // There is no await between the final policy read, conditional issuance,
    // and the authority's synchronous locked claim + callback invocation.
    // The callback must begin the provider handoff synchronously.
    let outcome;
    try {
      outcome = await authority.dispatch({ ...binding, grant_id: grant.grant_id,
        execute: (request, { idempotencyKey }) => execute(request, { idempotencyKey }) });
    } catch { return { protocol: "aml-revocable-prepared-mail-result/1", plan,
      receipt: receipt("unknown", "authority_dispatch_error"), dispatch_count: null }; }
    const expectedCount = { returned: 1, outcome_unknown: 1, blocked: 0, indeterminate: 0 };
    if (!outcome || !Object.hasOwn(expectedCount, outcome.status) ||
        outcome.dispatch_count !== expectedCount[outcome.status]) {
      return { protocol: "aml-revocable-prepared-mail-result/1", plan,
        receipt: receipt("unknown", "invalid_authority_outcome"), dispatch_count: null };
    }
    const status = outcome.status === "returned" ? "dispatched" :
      outcome.status === "outcome_unknown" || outcome.status === "indeterminate" ? "unknown" : "blocked";
    return { protocol: "aml-revocable-prepared-mail-result/1", plan,
      receipt: receipt(status, outcome.reason), dispatch_count: outcome.dispatch_count,
      ...(outcome.status === "returned" ? { result: outcome.result } : {}) };
  };
}
