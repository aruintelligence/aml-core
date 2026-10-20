// Project-maintained browser-compatible ES module. Uses WebCrypto, TextEncoder,
// and ordinary JSON values; imports no Node module or action-boundary code.
// The host fixture below simulates callbacks, with no external side effect.
const effects = new Set(["read", "write", "send", "pay", "delete"]);
const isObject = v => v !== null && typeof v === "object" && !Array.isArray(v);
const fieldsAre = (value, fields) => isObject(value) &&
  Object.keys(value).sort().join("|") === [...fields].sort().join("|");
const validText = v => typeof v === "string" && Boolean(v.trim()) && v.length <= 256;

function ordered(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (Array.isArray(value)) return value.map(ordered);
  if (isObject(value)) return Object.fromEntries(Object.keys(value).sort().map(k => [k, ordered(value[k])]));
  throw new Error("unsupported_json_subset");
}
const wire = value => JSON.stringify(ordered(value));
async function digest(value) {
  const bytes = new TextEncoder().encode(wire(value));
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map(n => n.toString(16).padStart(2, "0")).join("");
}
function validProposal(p) {
  return fieldsAre(p, ["protocol", "tool", "effect", "resource", "purpose", "arguments"]) &&
    p.protocol === "aml-proposed-action/1" && effects.has(p.effect) && isObject(p.arguments) &&
    [p.tool, p.resource, p.purpose].every(validText) &&
    new TextEncoder().encode(wire(p)).length <= 65536;
}
function validPolicy(policy) {
  return isObject(policy) && policy.protocol === "aml-action-policy/1" &&
    Array.isArray(policy.rules) && policy.rules.every(r =>
      fieldsAre(r, ["tool", "effect", "resource", "requires_approval"]) &&
      typeof r.tool === "string" && Boolean(r.tool.trim()) &&
      typeof r.resource === "string" && Boolean(r.resource.trim()) &&
      effects.has(r.effect) && typeof r.requires_approval === "boolean");
}
export async function runWebCryptoCase(input) {
  if (input.protocol !== "aml-action-challenge-case/1") throw new Error("Unknown case protocol");
  const frozen = JSON.parse(JSON.stringify(input.proposal));
  let decision = "deny", reason = "invalid_proposal", proposalHash = null;
  if (validProposal(frozen)) {
    proposalHash = await digest(frozen);
    if (!validPolicy(input.policy)) {
      reason = "invalid_policy"; proposalHash = null;
    } else {
      const matches = input.policy.rules.filter(r =>
        r.tool === frozen.tool && r.effect === frozen.effect && r.resource === frozen.resource);
      if (matches.length > 1) { reason = "ambiguous_policy"; proposalHash = null; }
      else if (matches.length === 0) reason = "no_exact_rule";
      else { reason = "exact_rule"; decision = matches[0].requires_approval ? "requires_approval" : "allow"; }
    }
  }
  const plan = { protocol: "aml-action-plan/1", proposal_sha256: proposalHash, decision, reason };
  const host = input.host;
  let status = "blocked", receiptReason = reason, calls = 0, executed = null;
  if (decision !== "deny") {
    if (decision === "requires_approval" && host.approval === "missing") receiptReason = "approval_unavailable";
    else if (decision === "requires_approval" && host.approval === "throw") receiptReason = "approval_error";
    else if (decision === "requires_approval" && host.approval === "fixed" &&
             host.approval_digest_sha256 !== proposalHash) receiptReason = "approval_missing_or_mismatched";
    else if (decision === "requires_approval" && host.remove_policy_rule) receiptReason = "policy_changed";
    else {
      // A host hook can change caller-owned data, never this original snapshot.
      calls = 1;
      executed = frozen;
      [status, receiptReason] = host.tool === "throw"
        ? ["unknown", "host_dispatch_error"] : ["dispatched", "host_dispatch_returned"];
    }
  }
  return { protocol: "aml-action-boundary-result/1", plan,
    receipt: { protocol: "aml-action-dispatch/1", proposal_sha256: proposalHash,
      policy_decision: decision, execution_status: status, reason: receiptReason },
    tool_calls: calls, executed_proposal: executed };
}
