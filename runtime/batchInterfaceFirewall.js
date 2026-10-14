// runtime/batchInterfaceFirewall.js
// Evaluate multiple interface intents under one deployment policy while preserving per-intent evidence.

import { createDeploymentFirewall } from "./deploymentFirewall.js";

export function evaluateInterfaceBatch(intents, options = {}) {
  if (!Array.isArray(intents)) throw new TypeError("intents must be an array.");
  const maxItems = options.max_items ?? 100;
  if (!Number.isInteger(maxItems) || maxItems <= 0) {
    throw new Error("max_items must be a positive integer.");
  }
  if (intents.length > maxItems) {
    throw new Error(`AML_BATCH_LIMIT_EXCEEDED:${intents.length}>${maxItems}`);
  }
  const { stream_ids: streamIds, ...evaluationOptions } = options;
  if (streamIds !== undefined) {
    if (!Array.isArray(streamIds) || streamIds.length !== intents.length ||
        streamIds.some(id => typeof id !== "string" || id.length === 0) ||
        new Set(streamIds).size !== streamIds.length) {
      throw new TypeError("stream_ids must contain one unique nonempty string per intent.");
    }
    if (options.stream_id !== undefined) {
      throw new TypeError("stream_id and stream_ids are mutually exclusive.");
    }
  }

  const firewall = createDeploymentFirewall(evaluationOptions);
  const results = intents.map((intent, index) => {
    const evaluation = firewall.evaluate(intent, streamIds === undefined
      ? evaluationOptions : { ...evaluationOptions, stream_id: streamIds[index] });
    return {
      index,
      transmission: intent?.transmission ?? null,
      aml_allowed: evaluation.aml_allowed,
      effective_allowed: evaluation.effective_allowed,
      would_suppress: evaluation.would_suppress,
      evaluation_error: evaluation.evaluation_error,
      receipt_sha256: evaluation.result?.receipt?.receipt_sha256 ?? null,
      evaluation
    };
  });

  return {
    protocol: "ĀML Batch Interface Result",
    version: "1.0",
    mode: options.mode || "enforce",
    failure_mode: options.failure_mode || "closed",
    total: results.length,
    aml_allowed: results.filter(item => item.aml_allowed === true).length,
    aml_suppressed: results.filter(item => item.aml_allowed === false).length,
    evaluation_errors: results.filter(item => item.evaluation_error).length,
    effective_allowed: results.filter(item => item.effective_allowed === true).length,
    results
  };
}
