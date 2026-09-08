// compiler/policyMatrix.js
// ĀML v1.3 — compare one source across many policies/profiles at once.

import { compileSource } from "./compiler.js";
import { resolvePolicy } from "../runtime/policyEngine.js";
import { resolvePolicyProfile } from "../runtime/policyProfiles.js";
import { policyFromProfile } from "../runtime/policyComposition.js";

function resolveTarget(target) {
  if (typeof target !== "string") throw new TypeError("Policy matrix targets must be policy/profile IDs.");
  try {
    return { id: target, kind: "policy", policy: resolvePolicy(target) };
  } catch {}
  const profile = resolvePolicyProfile(target);
  return { id: profile.id, kind: "profile", policy: policyFromProfile(profile) };
}

function decisionKey(decision, index) {
  return decision.identifier || decision.name || `${decision.node_type}:${index}`;
}

export function policyMatrix(source, targets, options = {}) {
  if (typeof source !== "string") throw new TypeError("ĀML source must be a string.");
  if (!Array.isArray(targets) || targets.length < 2) throw new Error("policyMatrix requires at least two targets.");

  const context = options.context || {};
  const timestamp = options.timestamp ?? "1970-01-01T00:00:00.000Z";
  const resolved = targets.map(resolveTarget);
  const runs = resolved.map(target => {
    const compiled = compileSource(source, { policy: target.policy, context, timestamp });
    return { ...target, decisions: compiled.renderDecisions };
  });

  const keys = [...new Set(runs.flatMap(run => run.decisions.map(decisionKey)))].sort();
  const rows = keys.map(key => {
    const outcomes = {};
    for (const run of runs) {
      const index = run.decisions.findIndex((decision, i) => decisionKey(decision, i) === key);
      const decision = index >= 0 ? run.decisions[index] : null;
      outcomes[run.id] = decision ? {
        render_allowed: decision.render_allowed,
        policy_id: decision.policy_id,
        rationale: decision.policy_rationale ?? decision.rationale ?? null
      } : null;
    }
    const booleans = Object.values(outcomes).filter(Boolean).map(item => item.render_allowed);
    return { key, disagreement: new Set(booleans).size > 1, outcomes };
  });

  return {
    protocol: "ĀML Policy Matrix",
    version: "1.0",
    context: structuredClone(context),
    targets: resolved.map(({ id, kind }) => ({ id, kind })),
    nodes: rows.length,
    disagreements: rows.filter(row => row.disagreement).length,
    rows
  };
}
