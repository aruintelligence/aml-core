import { verifiedGateEvent } from "./playground-live.js";

// A local, unsigned snapshot of the project-authored browser experiment.
// The source digest identifies the exact text; it does not attest to the run.
export async function createLocalRunRecord({ source, decisions, entries, pageUrl, generatedAt = new Date().toISOString() }) {
  if (typeof source !== "string" || !source.trim() || !Array.isArray(decisions) ||
      !Array.isArray(entries) || !entries.length || entries.length > decisions.length) {
    throw new RangeError("A compiled source and at least one observed gate are required");
  }
  const seen = new Set();
  const gates = entries.map(({ index, declaration, detail, hidden, observedAt }) => {
    if (!Number.isInteger(index) || index < 0 || index >= decisions.length || seen.has(index) ||
        !verifiedGateEvent(detail, decisions[index], declaration, hidden)) {
      throw new RangeError("A browser event did not match its unique compiler decision");
    }
    seen.add(index);
    const decision = decisions[index];
    return {
      decision_index: index,
      identifier: decision.identifier,
      declaration: {
        purpose: declaration.purpose, label: declaration.label,
        attention_cost: declaration.attention, restoration_value: declaration.restoration
      },
      compiler: { render_allowed: decision.render_allowed, timestamp: decision.timestamp },
      browser: {
        observed_at: observedAt, ok: detail.ok, render_allowed: detail.render_allowed,
        effective_rendered: detail.effective_rendered,
        deployment_mode: detail.deployment_mode, failure_mode: detail.failure_mode
      },
      matched: true
    };
  });
  const bytes = new TextEncoder().encode(source);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  const sourceSha256 = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
  const page = new URL(pageUrl);
  return {
    format: "aml-playground-local-run/v1",
    generated_at: generatedAt,
    scope: "Unsigned project-authored browser self-check. Declared inputs are not measurements or independent validation.",
    page: page.origin + page.pathname,
    source_sha256: sourceSha256,
    source,
    compiler_decision_count: decisions.length,
    previewed_gate_count: gates.length,
    gates
  };
}
