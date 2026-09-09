// runtime/interfaceFirewall.js
// ĀML mainstream surface — accountable interface firewall between AI intent and UI output.

import { executeAccountableIntent, verifyExecutionReceipt } from "../compiler/accountablePipeline.js";
import { compileSource } from "../compiler/compiler.js";
import { buildProvenanceGraph, verifyProvenanceGraph } from "../compiler/provenanceGraph.js";
import { auditAccessibilityTree } from "./accessibilityAudit.js";

export function createInterfaceFirewall(options = {}) {
  const profile = options.profile || "human_first";
  const defaultContext = structuredClone(options.context || {});

  return {
    protocol: "ĀML Interface Firewall",
    version: "1.0",
    profile,
    inspect(intent, runOptions = {}) {
      const context = { ...defaultContext, ...(runOptions.context || {}) };
      const selectedProfile = runOptions.profile || profile;
      const receipt = executeAccountableIntent(intent, {
        profile: selectedProfile,
        context,
        timestamp: runOptions.timestamp,
        stream_id: runOptions.stream_id
      });
      const compilation = compileSource(receipt.aml_source, {
        timestamp: runOptions.timestamp,
        context
      });
      const accessibility = auditAccessibilityTree(compilation.amt, context);
      const provenance = buildProvenanceGraph(receipt);
      return {
        profile: selectedProfile,
        receipt,
        receipt_verification: verifyExecutionReceipt(receipt),
        provenance,
        provenance_verification: verifyProvenanceGraph(provenance, receipt),
        accessibility
      };
    },
    enforce(intent, runOptions = {}) {
      const report = this.inspect(intent, runOptions);
      const denied = report.receipt.selected_render.decisions.filter(item => !item.render_allowed);
      return {
        allowed: denied.length === 0,
        denied_count: denied.length,
        allowed_count: report.receipt.selected_render.decisions.length - denied.length,
        html: report.receipt.selected_render.html,
        decisions: report.receipt.selected_render.decisions,
        receipt: report.receipt,
        report
      };
    }
  };
}

export function enforceInterfaceIntent(intent, options = {}) {
  return createInterfaceFirewall(options).enforce(intent, options);
}
