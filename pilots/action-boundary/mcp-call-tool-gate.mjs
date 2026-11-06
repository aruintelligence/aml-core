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
      const bytes = canonicalJSONStringify(params.arguments, { maxArrayLength: 65_536 });
      if (Buffer.byteLength(bytes, "utf8") > 60_000) return reject("arguments_too_large");
      args = JSON.parse(bytes);
      if (validateArgs(structuredClone(args), context) !== true) return reject("invalid_arguments");
    } catch { return reject("invalid_arguments"); }

    let outcome;
    try { outcome = await guarded(args, context); }
    catch { return reject("host_mapping_or_policy_error"); }
    const status = outcome.receipt.execution_status;
    const result = outcome.result;
    let mcp_result_status;
    let readableResult = true;
    try {
      mcp_result_status = status === "blocked" ? "not_called" :
        status === "unknown" ? "unknown" :
        !plain(result) ? "invalid_result" :
        result.isError === true ? "tool_error" :
        result.resultType === "input_required" ? "input_required" : "returned";
    } catch {
      // The callback has already returned. Keep its dispatched receipt even if
      // an untrusted result getter/proxy fails during local classification.
      mcp_result_status = "invalid_result";
      readableResult = false;
    }
    return { protocol: "aml-mcp-call-tool-result/1", server_key: serverKey,
      tool_name: name, rejection: null, plan: outcome.plan, receipt: outcome.receipt,
      mcp_result_status, ...(readableResult && Object.hasOwn(outcome, "result") ? { result } : {}) };
  };
}

// Strict construction profile for effectful integrations. The /1 boundary
// retains its documented optional consumer for existing experiments; callers
// choosing this profile cannot accidentally omit the host's atomic claim.
export function createOneUseMCPCallToolGate(options = {}) {
  if (typeof options.consumeApproval !== "function") {
    throw new TypeError("A host-owned atomic consumeApproval callback is required");
  }
  return createMCPCallToolGate(options);
}

// A versioned host profile for a specific authenticated MCP connection/account.
// The host must read identity from the active connection, not from agent input
// or an unrelated cached configuration string.
export function mcpConnectionResource(connectionIdentity, destination) {
  if (typeof connectionIdentity !== "string" || !connectionIdentity.trim() ||
      typeof destination !== "string" || !destination.trim()) {
    throw new TypeError("A host connection identity and destination are required");
  }
  const resource = canonicalJSONStringify({ connection_identity: connectionIdentity, destination });
  if (resource.length > 256) throw new TypeError("Bound MCP resource exceeds proposal limit");
  return resource;
}

export function createConnectionBoundMCPCallToolGate({
  client, connectionIdentity, readConnectionIdentity, resourceFor, consumeApproval, ...options
} = {}) {
  if (typeof readConnectionIdentity !== "function" || typeof resourceFor !== "function" ||
      typeof consumeApproval !== "function" ||
      typeof client?.callTool !== "function") {
    throw new TypeError("A connected client, live identity reader, destination mapper, and one-use consumer are required");
  }
  // The symbol is private to this closure, so a provider cannot accidentally
  // return the same sentinel. No provider call occurs on this branch.
  const changed = Symbol("mcp_connection_changed");
  const currentIdentity = () => {
    const current = readConnectionIdentity();
    if (typeof current !== "string" || !current.trim()) throw new Error("invalid_connection_identity");
    return current;
  };
  const gate = createMCPCallToolGate({ ...options,
    client: { callTool: async call => {
      try { if (currentIdentity() !== connectionIdentity) return changed; }
      catch { return changed; }
      return client.callTool(call);
    } },
    resourceFor: (args, context) => {
      if (currentIdentity() !== connectionIdentity) throw new Error("connection_changed");
      return mcpConnectionResource(connectionIdentity, resourceFor(args, context));
    }, consumeApproval
  });
  return async (params, context) => {
    const outcome = await gate(params, context);
    if (outcome.result !== changed) return outcome;
    // The callback was entered by the boundary, but the MCP transport was not.
    // Report the narrower observed state and keep the consumed grant spent.
    const { result, ...withoutResult } = outcome;
    return { ...withoutResult, receipt: { ...outcome.receipt,
      execution_status: "blocked", reason: "connection_changed" },
      mcp_result_status: "not_called" };
  };
}
