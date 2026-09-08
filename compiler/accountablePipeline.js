// compiler/accountablePipeline.js
// ĀML v1.2 — end-to-end accountable AI intent execution pipeline.

import crypto from "node:crypto";
import { generateAMLFromIntent } from "./intentCompiler.js";
import { compileSource } from "./compiler.js";
import { simulatePolicies } from "./policySimulator.js";
import { policyFromProfile } from "../runtime/policyComposition.js";
import { resolvePolicyProfile } from "../runtime/policyProfiles.js";

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : stableStringify(value)).digest("hex");
}

export function executeAccountableIntent(intent, options = {}) {
  const timestamp = options.timestamp ?? new Date().toISOString();
  const profile = resolvePolicyProfile(options.profile || "calm_default");
  const context = options.context || {};
  const amlSource = generateAMLFromIntent(intent);

  const simulations = simulatePolicies(amlSource, profile.policies, {
    timestamp,
    context
  });

  const composedPolicy = policyFromProfile(profile);
  const selectedCompilation = compileSource(amlSource, {
    timestamp,
    policy: composedPolicy,
    context
  });

  const receipt = {
    protocol: "ĀML Accountable Execution Receipt",
    version: "1.0",
    timestamp,
    profile: {
      id: profile.id,
      description: profile.description,
      policies: profile.policies
    },
    context: structuredClone(context),
    intent_sha256: sha256(intent),
    aml_sha256: sha256(amlSource),
    simulation_sha256: sha256(simulations),
    output_sha256: sha256(selectedCompilation.html),
    decision_sha256: sha256(selectedCompilation.renderDecisions),
    intent: structuredClone(intent),
    aml_source: amlSource,
    simulations,
    selected_render: {
      policy_id: composedPolicy.id,
      allowed: selectedCompilation.renderDecisions.filter(item => item.render_allowed).length,
      suppressed: selectedCompilation.renderDecisions.filter(item => !item.render_allowed).length,
      decisions: selectedCompilation.renderDecisions,
      html: selectedCompilation.html
    }
  };

  receipt.receipt_sha256 = sha256({ ...receipt, receipt_sha256: undefined });
  return receipt;
}

export function verifyExecutionReceipt(receipt) {
  if (!receipt || receipt.protocol !== "ĀML Accountable Execution Receipt") {
    throw new Error("Invalid ĀML accountable execution receipt.");
  }

  const expected = sha256({ ...receipt, receipt_sha256: undefined });
  return {
    verified: expected === receipt.receipt_sha256,
    expected_sha256: expected,
    receipt_sha256: receipt.receipt_sha256
  };
}
