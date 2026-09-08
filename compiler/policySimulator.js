// compiler/policySimulator.js
// Run identical AML meaning through multiple policy engines for comparison.

import { tokenize } from "./lexer.js";
import { parse } from "./parser.js";
import { buildAMT } from "./amtBuilder.js";
import { evaluateRenderDecisions } from "./renderEvaluator.js";

export function simulatePolicies(source, policies, options = {}) {
  if (typeof source !== "string") throw new TypeError("ĀML source must be a string.");
  if (!Array.isArray(policies) || policies.length === 0) {
    throw new Error("At least one policy is required for simulation.");
  }

  const tokens = tokenize(source);
  const ast = parse(tokens);
  const amt = buildAMT(ast);
  const timestamp = options.timestamp ?? "1970-01-01T00:00:00.000Z";
  const context = options.context ?? {};

  const runs = policies.map(policy => {
    const decisions = evaluateRenderDecisions(amt, { timestamp, policy, context });
    return {
      policy: typeof policy === "string" ? policy : policy?.id || "custom",
      allowed: decisions.filter(item => item.render_allowed).length,
      suppressed: decisions.filter(item => !item.render_allowed).length,
      decisions
    };
  });

  return {
    protocol: "ĀML Counterfactual Policy Simulation",
    version: "1.0",
    policy_count: runs.length,
    decision_nodes: runs[0]?.decisions.length || 0,
    context: structuredClone(context),
    runs
  };
}
