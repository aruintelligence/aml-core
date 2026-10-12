import { compileSourceBrowser } from "./aml-browser.js";
import { studioHandoffUrls } from "./playground-handoff.js";
import { parseSharedIntegration } from "./quickstart-core.js";

export const MAX_RECORD_CHARS = 1_000_000;

function check(id, label, pass, detail) { return { id, label, pass, detail }; }

function gateCheck(gate, decisions, handoffs, seen) {
  const index = gate?.decision_index;
  const decision = Number.isInteger(index) ? decisions[index] : null;
  let expected = null;
  try { expected = handoffs[index] ? parseSharedIntegration(handoffs[index]) : null; }
  catch { /* An unrepresentable node cannot be checked as a live gate. */ }
  const declaration = gate?.declaration;
  const browser = gate?.browser;
  const pass = !!decision && !!expected && !seen.has(index) && gate.matched === true &&
    gate.identifier === decision.identifier &&
    declaration?.label === expected.label && declaration?.purpose === expected.purpose &&
    declaration?.attention_cost === expected.attention &&
    declaration?.restoration_value === expected.restoration &&
    gate.compiler?.render_allowed === decision.render_allowed &&
    browser?.ok === true && browser.deployment_mode === "enforce" &&
    browser.failure_mode === "closed" && browser.render_allowed === decision.render_allowed &&
    browser.effective_rendered === decision.render_allowed;
  if (Number.isInteger(index)) seen.add(index);
  return {
    index: Number.isInteger(index) ? index : null,
    identifier: typeof gate?.identifier === "string" ? gate.identifier : "Unknown gate",
    pass,
    recorded: browser?.effective_rendered === true ? "visible" : browser?.effective_rendered === false ? "withheld" : "unknown",
    detail: pass ? `Declared ${expected.restoration} ${expected.restoration >= expected.attention ? "≥" : "<"} ${expected.attention}; recorded ${browser.effective_rendered ? "visible" : "withheld"}.` :
      "The saved gate fields do not agree with this source and the current project compiler."
  };
}

// Rechecks internal consistency only. JSON can be fabricated; this does not
// authenticate a historical browser event or independently validate a claim.
export async function checkLocalRun(input) {
  if (typeof input !== "string" || !input.trim() || input.length > MAX_RECORD_CHARS)
    throw new RangeError("Paste a local run JSON record under 1 MB");
  let record;
  try { record = JSON.parse(input); }
  catch { throw new RangeError("This is not valid JSON"); }
  if (!record || typeof record !== "object" || Array.isArray(record))
    throw new RangeError("The JSON must contain a local run object");

  const source = record.source;
  const gates = record.gates;
  let pageIsWeb = false;
  try { pageIsWeb = ["https:", "http:"].includes(new URL(record.page).protocol); }
  catch { /* A relative or malformed page is not a supported record origin. */ }
  const shape = record.format === "aml-playground-local-run/v1" &&
    typeof source === "string" && !!source.trim() &&
    pageIsWeb &&
    /^[0-9a-f]{64}$/.test(record.source_sha256 || "") &&
    Array.isArray(gates) && gates.length >= 1 && gates.length <= 6 &&
    record.previewed_gate_count === gates.length && Number.isInteger(record.compiler_decision_count);
  if (!shape) throw new RangeError("This is not a supported local run record");

  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(source));
  const sourceSha256 = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
  const checks = [check("hash", "Exact source fingerprint", sourceSha256 === record.source_sha256,
    sourceSha256 === record.source_sha256 ? "SHA-256 matches the source text in this file." : "SHA-256 differs from the source text in this file.")];

  let compiled = null;
  try { compiled = compileSourceBrowser(source); }
  catch { /* The recorded source no longer compiles with the current project engine. */ }
  const decisions = compiled?.renderDecisions || [];
  const compilerPass = !!compiled && decisions.length === record.compiler_decision_count;
  checks.push(check("compiler", "Current compiler replay", compilerPass,
    compilerPass ? `${decisions.length} decision(s) produced with the current project compiler.` :
      "The saved source could not reproduce the recorded decision count with the current project compiler."));

  let handoffs = [];
  if (compiled) {
    try { handoffs = studioHandoffUrls(compiled, record.page); }
    catch { /* A malformed page or handoff prevents gate comparison. */ }
  }
  const seen = new Set();
  const gateResults = gates.map(gate => gateCheck(gate, decisions, handoffs, seen));
  const gatePass = compilerPass && gateResults.every(gate => gate.pass);
  checks.push(check("gates", "Saved gate claims", gatePass,
    gatePass ? `${gateResults.length} saved gate outcome(s) agree with the declarations and replayed decisions.` :
      "One or more saved gate claims differ from the source, declaration, or replayed decision."));

  return { consistent: checks.every(item => item.pass), checks, gates: gateResults,
    source_sha256: sourceSha256, generated_at: record.generated_at || null };
}
