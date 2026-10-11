// Browser-side, project-authored mirror of the action pilot's narrow JSON path.
// It never grants authority or executes a tool. Keep the shared vector test in CI.
const EFFECTS = new Set(["read", "write", "send", "pay", "delete"]);
const PROPOSAL_KEYS = ["protocol", "tool", "effect", "resource", "purpose", "arguments"];
const RULE_KEYS = ["tool", "effect", "resource", "requires_approval"];
const plain = value => value !== null && typeof value === "object" && !Array.isArray(value);
const keysAre = (value, keys) => Object.keys(value).sort().join("|") === [...keys].sort().join("|");

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (plain(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  }
  throw new Error("invalid_proposal");
}

export async function planPreview(proposal, policy, subtle) {
  try {
    if (!plain(proposal) || !keysAre(proposal, PROPOSAL_KEYS) ||
        proposal.protocol !== "aml-proposed-action/1" || !EFFECTS.has(proposal.effect) ||
        !["tool", "resource", "purpose"].every(key => typeof proposal[key] === "string" &&
          proposal[key].trim() && proposal[key].length <= 256) || !plain(proposal.arguments)) {
      throw new Error("invalid_proposal");
    }
    const canonical_json = JSON.stringify(canonicalize(proposal));
    const bytes = new TextEncoder().encode(canonical_json);
    if (bytes.length > 65536) throw new Error("proposal_too_large");
    const digest = new Uint8Array(await subtle.digest("SHA-256", bytes));
    const proposal_sha256 = Array.from(digest, b => b.toString(16).padStart(2, "0")).join("");

    if (!plain(policy) || policy.protocol !== "aml-action-policy/1" || !Array.isArray(policy.rules)) {
      throw new Error("invalid_policy");
    }
    for (const rule of policy.rules) {
      if (!plain(rule) || !keysAre(rule, RULE_KEYS) ||
          !["tool", "resource"].every(key => typeof rule[key] === "string" && rule[key].trim()) ||
          !EFFECTS.has(rule.effect) || typeof rule.requires_approval !== "boolean") {
        throw new Error("invalid_policy");
      }
    }
    const matches = policy.rules.filter(rule => rule.tool === proposal.tool &&
      rule.effect === proposal.effect && rule.resource === proposal.resource);
    if (matches.length > 1) throw new Error("ambiguous_policy");
    const rule = matches[0];
    return { protocol: "aml-action-plan/1", proposal_sha256,
      decision: !rule ? "deny" : rule.requires_approval ? "requires_approval" : "allow",
      reason: rule ? "exact_rule" : "no_exact_rule", canonical_json };
  } catch (error) {
    return { protocol: "aml-action-plan/1", proposal_sha256: null, decision: "deny",
      reason: ["invalid_proposal", "proposal_too_large", "invalid_policy", "ambiguous_policy"]
        .includes(error.message) ? error.message : "invalid_proposal", canonical_json: null };
  }
}

export function rehearse(plan, approvedDigest, uncertain = false, grantConsumed = false) {
  if (plan.decision === "deny") return { outcome: "blocked", reason: plan.reason };
  if (plan.decision === "requires_approval" && approvedDigest !== plan.proposal_sha256) {
    return { outcome: "blocked", reason: "approval_missing_or_mismatched" };
  }
  if (plan.decision === "requires_approval" && grantConsumed) {
    return { outcome: "blocked", reason: "approval_reused_or_expired" };
  }
  return uncertain ? { outcome: "unknown", reason: "simulated_dispatch_exception" } :
    { outcome: "would_dispatch", reason: "simulation_only" };
}
