// A narrow A2UI v1.0 callRendererFunction integration for one host-owned
// catalog entry. The renderer still owns its session, active catalog, schema,
// transport, and functionCallId lifecycle. This gate adds an AML action check
// before a host callback with an external effect.
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { createGuardedToolExecute } from "../../pilots/action-boundary/guarded-tool.mjs";

const isObject = value => value !== null && typeof value === "object" &&
  !Array.isArray(value);
const text = value => typeof value === "string" && value.trim().length > 0;
const agentCallers = new Set(["agentOnly", "rendererOrAgent"]);
const callers = new Set([...agentCallers, "rendererOnly"]);

function errorResponse(functionCallId, code, message) {
  return { version: "v1.0", error: { code, message, functionCallId } };
}

export function createA2UIFunctionGate({
  catalogId, functionName, allowedCallers, validateArgs,
  tool, effect, purpose, resourceFor, policy, requestApproval,
  consumeApproval, execute
} = {}) {
  if (!text(catalogId) || !text(functionName) || !callers.has(allowedCallers) ||
      typeof validateArgs !== "function") {
    throw new TypeError("A host-owned catalog entry and argument validator are required");
  }
  // All callbacks come from trusted renderer configuration, never the agent.
  const guarded = createGuardedToolExecute({
    tool, effect, purpose, resourceFor, policy, requestApproval, consumeApproval, execute
  });

  return async function handleAgentFunctionCall(envelope, context) {
    const call = envelope?.callRendererFunction;
    const id = call?.functionCallId;
    // Without a usable correlation ID, the renderer cannot safely return an
    // A2UI function response. The caller must reject the malformed envelope.
    if (!text(id) || id.length > 256) throw new TypeError("invalid A2UI functionCallId");
    if (envelope.version !== "v1.0" || !isObject(call) ||
        !isObject(call.callFunction) ||
        call.callFunction.catalogId !== catalogId ||
        call.callFunction.call !== functionName ||
        !agentCallers.has(allowedCallers)) {
      return { response: errorResponse(id, "INVALID_FUNCTION_CALL",
        "Function is not available for agent invocation."), aml: null };
    }

    const args = call.callFunction.args === undefined ? {} : call.callFunction.args;
    let valid = false;
    if (isObject(args)) {
      try { valid = validateArgs(args, context) === true; } catch { /* deny */ }
    }
    if (!valid) return { response: errorResponse(id, "INVALID_FUNCTION_CALL",
      "Function arguments did not match the host schema."), aml: null };

    let aml;
    try { aml = await guarded(args, context); }
    catch {
      // A host mapping/configuration failure must still yield a correlated
      // protocol response. Conservatively do not assert that no effect ran.
      return { response: { version: "v1.0", rendererFunctionResponse: {
        functionCallId: id, error: { code: "EXECUTION_FAILED",
          message: "Host boundary failed; outcome is uncertain. Do not retry automatically." }
      } }, aml: null };
    }
    if (aml.receipt.execution_status === "blocked") {
      return { response: { version: "v1.0", rendererFunctionResponse: {
        functionCallId: id, error: { code: "ACTION_BLOCKED",
          message: "Host action policy or approval blocked this call." }
      } }, aml };
    }
    if (aml.receipt.execution_status === "unknown") {
      return { response: { version: "v1.0", rendererFunctionResponse: {
        functionCallId: id, error: { code: "EXECUTION_FAILED",
          message: "Tool outcome is uncertain; do not retry automatically." }
      } }, aml };
    }
    // A2UI values must be JSON transport data. Failure here happens AFTER the
    // callback; keep the dispatched receipt and never retry automatically.
    let value;
    try {
      value = JSON.parse(canonicalJSONStringify({
        value: aml.result === undefined ? null : aml.result
      })).value;
    } catch {
      return { response: { version: "v1.0", rendererFunctionResponse: {
        functionCallId: id, error: { code: "EXECUTION_FAILED",
          message: "The callback returned a non-JSON value; do not retry automatically." }
      } }, aml: { protocol: aml.protocol, plan: aml.plan, receipt: aml.receipt } };
    }
    return { response: { version: "v1.0", rendererFunctionResponse: {
      functionCallId: id, value
    } }, aml };
  };
}
