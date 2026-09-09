// compiler/policyDiff.js
// ĀML v1.3 — compare policy outcomes over identical source/context.

import { compileSource } from "./compiler.js";
import { policyFromProfile } from "../runtime/policyComposition.js";
import { resolvePolicyProfile } from "../runtime/policyProfiles.js";
import { resolvePolicy } from "../runtime/policyEngine.js";
import { buildPairedComparisonIndexes } from "../runtime/comparisonIdentity.js";

function normalizeTarget(target) {
  if (typeof target === "string") {
    try {
      return { id: target, policy: resolvePolicy(target), kind: "policy" };
    } catch {}
    const profile = resolvePolicyProfile(target);
    return { id: profile.id, policy: policyFromProfile(profile), kind: "profile" };
  }
  if (target && Array.isArray(target.policies)) {
    const profile = resolvePolicyProfile(target);
    return { id: profile.id, policy: policyFromProfile(profile), kind: "profile" };
  }
  if (target && typeof target.evaluate === "function") {
    return { id: target.id || "custom", policy: target, kind: "policy" };
  }
  throw new Error("Invalid ĀML policy diff target.");
}

function keyFor(decision, index) {
  return decision.identifier || decision.name || `${decision.node_type}:${index}`;
}

export function policyDiff(source, leftTarget, rightTarget, options = {}) {
  const timestamp = options.timestamp ?? "1970-01-01T00:00:00.000Z";
  const context = options.context || {};
  const left = normalizeTarget(leftTarget);
  const right = normalizeTarget(rightTarget);
  const leftResult = compileSource(source, { timestamp, context, policy: left.policy });
  const rightResult = compileSource(source, { timestamp, context, policy: right.policy });

  const paired = buildPairedComparisonIndexes(leftResult.renderDecisions, rightResult.renderDecisions, keyFor);
  const leftMap = paired.left.index;
  const rightMap = paired.right.index;
  const keys = [...new Set([...leftMap.keys(), ...rightMap.keys()])].sort();
  const changes = [];

  for (const key of keys) {
    const a = leftMap.get(key) || null;
    const b = rightMap.get(key) || null;
    if (!a || !b || a.render_allowed !== b.render_allowed || JSON.stringify(a.policy_rationale) !== JSON.stringify(b.policy_rationale)) {
      changes.push({
        key,
        identity_ambiguous: key.includes("#") && paired.ambiguous_identity_keys.some(entry => key.startsWith(`${entry.key}#`)),
        left: a && { render_allowed: a.render_allowed, policy_id: a.policy_id, rationale: a.policy_rationale },
        right: b && { render_allowed: b.render_allowed, policy_id: b.policy_id, rationale: b.policy_rationale }
      });
    }
  }

  return {
    protocol: "ĀML Policy Diff",
    version: "1.0",
    context: structuredClone(context),
    left: { id: left.id, kind: left.kind },
    right: { id: right.id, kind: right.kind },
    ambiguous_identity_keys: paired.ambiguous_identity_keys,
    identity_ambiguity_detected: paired.ambiguous_identity_keys.length > 0,
    changed_decisions: changes.length,
    changes
  };
}
