// A narrow A2UI v1.0 callRendererFunction integration for one host-owned
// catalog entry. The renderer still owns its session, active catalog, schema,
// transport, and functionCallId lifecycle. This gate requires a host-owned
// invocation claim and adds an AML action check
// before a host callback with an external effect.
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { createGuardedToolExecute } from "./guarded-tool.mjs";

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
  consumeApproval, claimInvocation, execute
} = {}) {
  if (!text(catalogId) || !text(functionName) || !callers.has(allowedCallers) ||
      typeof validateArgs !== "function" || typeof claimInvocation !== "function") {
    throw new TypeError("A host-owned catalog entry, argument validator, and invocation claim are required");
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

    // Freeze input before awaiting the claim; the agent-facing object could be
    // changed by other code while the host's shared store is being consulted.
    let frozenArgs;
    try {
      const bytes = canonicalJSONStringify(args);
      if (Buffer.byteLength(bytes, "utf8") > 65536) throw new Error("oversize");
      frozenArgs = JSON.parse(bytes);
    } catch {
      return { response: errorResponse(id, "INVALID_FUNCTION_CALL",
        "Function arguments are not supported JSON data."), aml: null };
    }

    let claimed;
    try {
      claimed = await claimInvocation({ functionCallId: id }, context);
    } catch {
      // A store error must fail closed. Even if a claim marker was written,
      // no tool callback has been attempted by this invocation.
      return { response: errorResponse(id, "EXECUTION_FAILED",
        "Host invocation claim unavailable; no callback was attempted."),
        aml: null, invocation: "unavailable" };
    }
    if (claimed !== true) return { response: errorResponse(id, "INVALID_FUNCTION_CALL",
      "functionCallId was already used in this host session."),
      aml: null, invocation: "reused" };

    let aml;
    try { aml = await guarded(frozenArgs, context); }
    catch {
      // A host mapping/configuration failure must still yield a correlated
      // protocol response. Conservatively do not assert that no effect ran.
      return { response: { version: "v1.0", rendererFunctionResponse: {
        functionCallId: id, error: { code: "EXECUTION_FAILED",
          message: "Host boundary failed; outcome is uncertain. Do not retry automatically." }
      } }, aml: null, invocation: "claimed" };
    }
    if (aml.receipt.execution_status === "blocked") {
      return { response: { version: "v1.0", rendererFunctionResponse: {
        functionCallId: id, error: { code: "ACTION_BLOCKED",
          message: "Host action policy or approval blocked this call." }
      } }, aml, invocation: "claimed" };
    }
    if (aml.receipt.execution_status === "unknown") {
      return { response: { version: "v1.0", rendererFunctionResponse: {
        functionCallId: id, error: { code: "EXECUTION_FAILED",
          message: "Tool outcome is uncertain; do not retry automatically." }
      } }, aml, invocation: "claimed" };
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
      } }, aml: { protocol: aml.protocol, plan: aml.plan, receipt: aml.receipt },
        invocation: "claimed" };
    }
    return { response: { version: "v1.0", rendererFunctionResponse: {
      functionCallId: id, value
    } }, aml, invocation: "claimed" };
  };
}
