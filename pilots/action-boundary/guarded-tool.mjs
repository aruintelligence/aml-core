// Experimental host-side adapter for a single function tool's execute callback.
// The host owns every option. Never construct policy, approval, or execute from
// model output. This returns receipts, not evidence of external delivery.
import { planAction, dispatchAction } from "./boundary.mjs";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

export function createGuardedToolExecute({
  tool, effect, purpose, resourceFor, policy, requestApproval, consumeApproval, execute
} = {}) {
  if (typeof tool !== "string" || !tool.trim() ||
      typeof effect !== "string" || !effect.trim() ||
      typeof purpose !== "string" || !purpose.trim() ||
      typeof resourceFor !== "function" || typeof execute !== "function" ||
      (requestApproval !== undefined && typeof requestApproval !== "function") ||
      (consumeApproval !== undefined && typeof consumeApproval !== "function") ||
      !policy || typeof policy !== "object") {
    throw new TypeError("A host-owned tool, effect, purpose, resourceFor, policy, and execute are required");
  }

  return async function guardedToolExecute(argumentsValue, context) {
    // Capture input once before asking a host mapper for the destination. A
    // getter or mapper must not shift the arguments between policy and dispatch.
    let argumentBytes;
    try {
      argumentBytes = canonicalJSONStringify(argumentsValue);
    } catch (error) {
      if (!String(error?.message).startsWith("AML_CANONICAL_JSON_")) throw error;
      const plan = { protocol: "aml-action-plan/1", proposal_sha256: null,
        decision: "deny", reason: error.message };
      return { protocol: "aml-guarded-tool-result/1", plan,
        receipt: { protocol: "aml-action-dispatch/1", proposal_sha256: null,
          policy_decision: "deny", execution_status: "blocked", reason: error.message } };
    }
    const mappedArguments = JSON.parse(argumentBytes);
    const resource = resourceFor(mappedArguments, context);
    if (typeof resource !== "string") throw new TypeError("resourceFor must return a string");
    if (canonicalJSONStringify(mappedArguments) !== argumentBytes) {
      throw new TypeError("resourceFor must not mutate arguments");
    }
    const proposal = {
      protocol: "aml-proposed-action/1", tool, effect, resource, purpose,
      arguments: JSON.parse(argumentBytes)
    };
    const plan = planAction(proposal, policy);
    const outcome = await dispatchAction(proposal, {
      policy,
      requestApproval: requestApproval && (input => requestApproval(input, context)),
      consumeApproval: consumeApproval && (input => consumeApproval(input, context)),
      executeTool: frozen => execute(frozen.arguments, context, frozen)
    });
    return {
      protocol: "aml-guarded-tool-result/1",
      plan,
      receipt: outcome.receipt,
      ...(Object.hasOwn(outcome, "result") ? { result: outcome.result } : {})
    };
  };
}

