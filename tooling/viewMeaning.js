// tooling/viewMeaning.js
// Human-readable inspector: the AML equivalent of "View Source" for accountable interfaces.

export function viewMeaning(receipt) {
  if (!receipt || receipt.protocol !== "ĀML Accountable Execution Receipt") {
    throw new Error("viewMeaning requires an ĀML accountable execution receipt.");
  }

  const decisions = receipt.selected_render?.decisions || [];
  return {
    protocol: "ĀML View Meaning",
    version: "1.0",
    profile: receipt.profile?.id || null,
    summary: {
      total_nodes: decisions.length,
      allowed: decisions.filter(item => item.render_allowed).length,
      suppressed: decisions.filter(item => !item.render_allowed).length,
      attention_consumed: receipt.attention_ledger?.consumed ?? null,
      attention_remaining: receipt.attention_ledger?.remaining ?? null,
      runtime_audit_verified: receipt.runtime_audit_verified === true
    },
    nodes: decisions.map(item => ({
      identifier: item.identifier || item.name || null,
      node_type: item.node_type || null,
      purpose: item.purpose || item.declared_purpose || null,
      attention_cost: item.attention_cost ?? null,
      restoration_value: item.restoration_value ?? null,
      policy_id: item.policy_id || null,
      render_allowed: item.render_allowed === true,
      rationale: item.policy_rationale ?? item.rationale ?? null,
      fallback_triggered: item.fallback_triggered === true
    })),
    integrity: {
      receipt_sha256: receipt.receipt_sha256 || null,
      audit_stream_sha256: receipt.audit_stream_sha256 || null,
      attention_ledger_sha256: receipt.attention_ledger_sha256 || null,
      signed: Boolean(receipt.signature)
    }
  };
}

export function formatMeaningReport(report) {
  if (!report || report.protocol !== "ĀML View Meaning") throw new Error("Invalid ĀML View Meaning report.");
  const lines = [
    `ĀML View Meaning — profile: ${report.profile ?? "unknown"}`,
    `nodes=${report.summary.total_nodes} allowed=${report.summary.allowed} suppressed=${report.summary.suppressed}`
  ];
  for (const node of report.nodes) {
    lines.push(`${node.render_allowed ? "ALLOW" : "SUPPRESS"} ${node.identifier ?? node.node_type ?? "node"} — purpose=${node.purpose ?? "undeclared"} — policy=${node.policy_id ?? "unknown"}`);
  }
  return lines.join("\n");
}
