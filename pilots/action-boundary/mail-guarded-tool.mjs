// Host-side function-tool execute adapter for one narrow mail schema.
// The host owns policy, approval, and the actual callback. No mail is sent here.
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { dispatchTargetBoundAction } from "./target-boundary.mjs";
import { mailTargetResource, resolveMailTarget } from "./mail-target-manifest.mjs";

export function createMailGuardedToolExecute({ purpose, policy, requestApproval,
  consumeApproval, execute } = {}) {
  if (typeof purpose !== "string" || !purpose.trim() || !policy ||
      typeof policy !== "object" || typeof execute !== "function" ||
      (requestApproval !== undefined && typeof requestApproval !== "function") ||
      (consumeApproval !== undefined && typeof consumeApproval !== "function")) {
    throw new TypeError("Host purpose, policy, and execute callback are required");
  }

  return async function mailGuardedExecute(args, context) {
    // Snapshot before deriving the resource. The schema rejects unknown fields,
    // so the callback must not have an unexamined delivery argument.
    const input = JSON.parse(canonicalJSONStringify(args));
    const resource = mailTargetResource(input).resource;
    const proposal = { protocol: "aml-proposed-action/1", tool: "send_message",
      effect: "send", resource, purpose, arguments: input };
    const outcome = await dispatchTargetBoundAction(proposal, {
      policy, resolveTarget: resolveMailTarget,
      requestApproval: requestApproval && (input => requestApproval(input, context)),
      consumeApproval: consumeApproval && (input => consumeApproval(input, context)),
      executeTool: frozen => execute(frozen.arguments, context, frozen)
    });
    return { protocol: "aml-guarded-tool-result/1", plan: outcome.plan, receipt: outcome.receipt,
      ...(Object.hasOwn(outcome, "result") ? { result: outcome.result } : {}) };
  };
}
