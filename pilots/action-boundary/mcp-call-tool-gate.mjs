// Narrow host-side MCP Client.callTool boundary. Tool descriptions and
// annotations from tools/list never authorize a call. The connected client,
// server key, schema validator, policy, and approval are host-owned.
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { createGuardedToolExecute } from "./guarded-tool.mjs";

const plain = x => x !== null && typeof x === "object" && !Array.isArray(x);
const validName = x => typeof x === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(x);
const validKey = x => typeof x === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(x);

export function createMCPCallToolGate({ client, serverKey, name, effect, purpose,
  validateArgs, resourceFor, policy, requestApproval, consumeApproval } = {}) {
  if (typeof client?.callTool !== "function" || !validKey(serverKey) || !validName(name) ||
      typeof validateArgs !== "function" || typeof resourceFor !== "function") {
    throw new TypeError("A connected host client, server key, tool name, schema, and destination mapper are required");
  }
  const tool = `mcp:${serverKey}:${name}`;
  const guarded = createGuardedToolExecute({ tool, effect, purpose,
    resourceFor, policy, requestApproval, consumeApproval,
    execute: args => client.callTool({ name, arguments: args }) });
  const reject = reason => ({ protocol: "aml-mcp-call-tool-result/1", server_key: serverKey,
    tool_name: name, rejection: reason, plan: null, receipt: null,
    mcp_result_status: "not_called" });

  return async function callToolWithAML(params, context) {
    // This example accepts only the ordinary name/arguments call shape. It
    // deliberately ignores all server-advertised annotations and rejects
    // unknown params rather than forwarding them to a possibly effectful SDK.
    if (!plain(params) || Object.keys(params).sort().join(",") !== "arguments,name" ||
        params.name !== name || !plain(params.arguments)) return reject("invalid_or_unregistered_call");
    let args;
    try {
      const bytes = canonicalJSONStringify(params.arguments);
      if (Buffer.byteLength(bytes, "utf8") > 60_000) return reject("arguments_too_large");
      args = JSON.parse(bytes);
      if (validateArgs(structuredClone(args), context) !== true) return reject("invalid_arguments");
    } catch { return reject("invalid_arguments"); }

    let outcome;
    try { outcome = await guarded(args, context); }
    catch { return reject("host_mapping_or_policy_error"); }
    const status = outcome.receipt.execution_status;
    const result = outcome.result;
    const mcp_result_status = status === "blocked" ? "not_called" :
      status === "unknown" ? "unknown" :
      !plain(result) ? "invalid_result" :
      result.isError === true ? "tool_error" :
      result.resultType === "input_required" ? "input_required" : "returned";
    return { protocol: "aml-mcp-call-tool-result/1", server_key: serverKey,
      tool_name: name, rejection: null, plan: outcome.plan, receipt: outcome.receipt,
      mcp_result_status, ...(Object.hasOwn(outcome, "result") ? { result } : {}) };
  };
}
