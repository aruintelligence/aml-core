// Experimental host-side adapter for a single function tool's execute callback.
// The host owns every option. Never construct policy, approval, or execute from
// model output. This returns receipts, not evidence of external delivery.
import { planAction, dispatchAction } from "./boundary.mjs";

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
    // resourceFor must synchronously derive the real destination from the same
    // arguments that execute receives. A mapping error throws before dispatch.
    const resource = resourceFor(argumentsValue, context);
    if (typeof resource !== "string") throw new TypeError("resourceFor must return a string");
    const proposal = {
      protocol: "aml-proposed-action/1", tool, effect, resource, purpose,
      arguments: argumentsValue
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
