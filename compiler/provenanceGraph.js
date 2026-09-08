// compiler/provenanceGraph.js
// ĀML v1.3 — hash-bound provenance graph for accountable execution artifacts.

import crypto from "node:crypto";

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

export function buildProvenanceGraph(receipt) {
  if (!receipt || receipt.protocol !== "ĀML Accountable Execution Receipt") throw new Error("Valid ĀML execution receipt required.");
  const nodes = [
    { id: "intent", kind: "intent", sha256: receipt.intent_sha256 },
    { id: "aml", kind: "generated_aml", sha256: receipt.aml_sha256 },
    { id: "simulation", kind: "policy_simulation", sha256: receipt.simulation_sha256 },
    { id: "decision", kind: "render_decision", sha256: receipt.decision_sha256 },
    { id: "output", kind: "rendered_output", sha256: receipt.output_sha256 },
    { id: "audit", kind: "runtime_audit_stream", sha256: receipt.audit_stream_sha256 },
    { id: "attention", kind: "attention_ledger", sha256: receipt.attention_ledger_sha256 },
    { id: "receipt", kind: "execution_receipt", sha256: receipt.receipt_sha256 }
  ];
  const edges = [
    { from: "intent", to: "aml", relation: "generated_as" },
    { from: "aml", to: "simulation", relation: "evaluated_by" },
    { from: "simulation", to: "decision", relation: "informed" },
    { from: "decision", to: "output", relation: "rendered_as" },
    { from: "decision", to: "attention", relation: "accounted_by" },
    { from: "intent", to: "audit", relation: "recorded_in" },
    { from: "output", to: "audit", relation: "recorded_in" },
    { from: "audit", to: "receipt", relation: "bound_into" },
    { from: "attention", to: "receipt", relation: "bound_into" },
    { from: "output", to: "receipt", relation: "bound_into" }
  ];
  const core = {
    protocol: "ĀML Provenance Graph",
    version: "1.0",
    receipt_sha256: receipt.receipt_sha256,
    nodes,
    edges
  };
  return { ...core, graph_sha256: sha256(core) };
}

export function verifyProvenanceGraph(graph, receipt) {
  if (!graph || graph.protocol !== "ĀML Provenance Graph") return { verified: false, reason: "invalid provenance graph" };
  const expected = buildProvenanceGraph(receipt);
  return {
    verified: expected.graph_sha256 === graph.graph_sha256 && stableStringify(expected.nodes) === stableStringify(graph.nodes) && stableStringify(expected.edges) === stableStringify(graph.edges),
    graph_hash_valid: expected.graph_sha256 === graph.graph_sha256,
    expected_graph_sha256: expected.graph_sha256,
    graph_sha256: graph.graph_sha256
  };
}
