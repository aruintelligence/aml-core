// runtime/streamingInterfaceFirewall.js
// Evaluate AI-generated interface nodes as they arrive.
// This reference implementation is process-local and ordered; it does not claim distributed stream semantics.

import { createDeploymentFirewall } from "./deploymentFirewall.js";

function assertNode(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) {
    throw new TypeError("stream node must be an object.");
  }
  if (typeof node.type !== "string" || node.type.length === 0) {
    throw new Error("stream node.type is required.");
  }
}

export function createStreamingInterfaceFirewall(options = {}) {
  const transmission = options.transmission || "streamed_interface";
  const deployment = createDeploymentFirewall(options);
  const entries = [];
  const identifiers = new Set();
  let closed = false;
  let sequence = 0;

  function push(node, runOptions = {}) {
    if (closed) throw new Error("AML_STREAM_ALREADY_FINALIZED");
    assertNode(node);
    if (node.identifier) {
      if (identifiers.has(node.identifier)) {
        throw new Error(`AML_STREAM_DUPLICATE_IDENTIFIER:${node.identifier}`);
      }
      identifiers.add(node.identifier);
    }

    sequence += 1;
    const intent = { transmission, nodes: [structuredClone(node)] };
    const evaluation = deployment.evaluate(intent, runOptions);
    const entry = {
      sequence,
      identifier: node.identifier || null,
      node: structuredClone(node),
      aml_allowed: evaluation.aml_allowed,
      effective_allowed: evaluation.effective_allowed,
      would_suppress: evaluation.would_suppress,
      evaluation_error: evaluation.evaluation_error,
      receipt_sha256: evaluation.result?.receipt?.receipt_sha256 || null,
      output_sha256: evaluation.result?.receipt?.output_sha256 || null,
      evaluation
    };
    entries.push(entry);
    return structuredClone(entry);
  }

  function snapshot() {
    const allowed = entries.filter(entry => entry.aml_allowed === true).length;
    const suppressed = entries.filter(entry => entry.aml_allowed === false).length;
    const errors = entries.filter(entry => entry.evaluation_error).length;
    const effectiveAllowed = entries.filter(entry => entry.effective_allowed === true).length;
    return {
      protocol: "ĀML Streaming Interface Snapshot",
      version: "1.0",
      transmission,
      finalized: closed,
      total: entries.length,
      allowed,
      suppressed,
      errors,
      effective_allowed: effectiveAllowed,
      entries: structuredClone(entries)
    };
  }

  function finalize() {
    if (!closed) closed = true;
    return {
      ...snapshot(),
      protocol: "ĀML Streaming Interface Result",
      finalized: true
    };
  }

  return {
    protocol: "ĀML Streaming Interface Firewall",
    version: "1.0",
    transmission,
    push,
    snapshot,
    finalize,
    get finalized() {
      return closed;
    }
  };
}
