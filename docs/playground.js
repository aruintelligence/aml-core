import { compileSourceBrowser } from "./aml-browser.js";
import { comparisonRestoration, comparisonSample, parsePlaygroundShare, playgroundShareUrl } from "./playground-core.js?v=declaration-dial-1";
import { studioHandoffUrls } from "./playground-handoff.js?v=compare-4";
import { downloadablePage, integrationSnippet, parseSharedIntegration } from "./quickstart-core.js?v=take-gate-1";
import { verifiedGateEvent } from "./playground-live.js?v=live-1";
import { createLocalRunRecord } from "./playground-record.js?v=local-run-1";

const $ = id => document.getElementById(id);
const source = $("source");
const output = $("output");
let result = null;
let view = "decisions";
let bridgeState = "loading";
let liveRun = null;
const MAX_LIVE_PREVIEWS = 6;

function clearRunRecord(message) {
  liveRun = null;
  $("record-count").textContent = "0 / 0 matched";
  $("run-record").dataset.state = "waiting";
  $("download-record").disabled = true;
  $("record-status").textContent = message;
}

function updateRunRecord() {
  const run = liveRun;
  if (!run) return;
  const matched = run.entries.size;
  const ready = run.expected > 0 && matched === run.expected && !run.failed && source.value === run.source;
  $("record-count").textContent = `${matched} / ${run.expected} matched`;
  $("run-record").dataset.state = ready ? "ready" : run.failed ? "blocked" : "waiting";
  $("download-record").disabled = !ready;
  $("record-status").textContent = ready ?
    "All shown gates match. Download the local, unsigned record of this exact source." :
    run.failed ? "A gate was unavailable or mismatched. No run record can be exported." :
    run.expected ? "Waiting for the shown browser gates to emit matching events." :
    "Compile an eligible engram to create a run record.";
}

function sample(restoration) {
  return `transmission "first_program" {
  engram offerPrompt {
    value: "Review the offer"
    purpose: "Invite a considered review"
    attention_cost: 5
    restoration_value: ${restoration}
  }
}`;
}

function element(tag, className, value) {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = String(value);
  return node;
}

function renderCards(decisions, handoffUrls) {
  const list = $("decision-cards");
  list.replaceChildren();
  if (!decisions.length) {
    list.append(element("p", "empty", "The program compiled, but no node declared inputs for a render decision. Add purpose, attention_cost, and restoration_value to an element."));
    return;
  }
  for (const [index, decision] of decisions.entries()) {
    const allowed = decision.render_allowed === true;
    const card = document.createElement("article");
    card.className = `decision-card ${allowed ? "allowed" : "suppressed"}`;
    const top = document.createElement("div");
    top.className = "decision-top";
    top.append(element("span", "number", String(index + 1).padStart(2, "0") + " / " + (decision.node_type || "NODE")));
    top.append(element("strong", "verdict", allowed ? "ALLOW" : "SUPPRESS"));
    card.append(top);
    card.append(element("h3", "", decision.identifier || decision.name || "Unnamed node"));
    card.append(element("p", "purpose", decision.purpose || "No purpose declared"));
    const values = document.createElement("div");
    values.className = "values";
    values.append(element("span", "", `Declared attention ${decision.attention_cost ?? "—"}`));
    values.append(element("span", "", `Declared restoration ${decision.restoration_value ?? "—"}`));
    card.append(values);
    if (handoffUrls[index]) {
      card.append(element("p", "handoff-note", "Explore this engram as a live browser gate. Its value becomes button text; the declared inputs carry over."));
      const link = element("a", "handoff-link", "See it as a live gate ↗");
      link.href = handoffUrls[index];
      card.append(link);
    }
    list.append(card);
  }
}

function takeGate(declaration, studioUrl) {
  const details = document.createElement("details");
  details.className = "gate-take";
  details.hidden = true;
  details.append(element("summary", "", "Take this gate into your page ↗"));
  details.append(element("p", "take-note", "This is one engram as a browser gate, not the entire program. It loads the changing project preview bridge; review and pin audited assets before production."));
  const code = element("pre", "gate-code", integrationSnippet(declaration));
  code.tabIndex = 0;
  code.setAttribute("aria-label", "Gate HTML to copy");
  details.append(code);
  const actions = document.createElement("div");
  actions.className = "take-actions";
  const copy = element("button", "", "Copy gate HTML");
  copy.type = "button";
  const download = element("button", "", "Download runnable page");
  download.type = "button";
  const studio = element("a", "", "Adjust in Studio ↗");
  studio.href = studioUrl;
  actions.append(copy, download, studio);
  details.append(actions);
  const status = element("p", "take-status", "Values are declared prototype inputs, not measurements.");
  status.setAttribute("role", "status");
  details.append(status);
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code.textContent);
      status.textContent = "Gate HTML copied. Paste it into your page and review the project preview dependency.";
    } catch {
      code.focus();
      status.textContent = "Clipboard unavailable. Select the gate HTML above to copy it.";
    }
  });
  download.addEventListener("click", () => {
    const file = new Blob([downloadablePage(declaration)], { type: "text/html;charset=utf-8" });
    const fileUrl = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = fileUrl;
    link.download = "my-aml-gate.html";
    link.click();
    setTimeout(() => URL.revokeObjectURL(fileUrl), 60_000);
    status.textContent = "Page downloaded. Open it with internet access; it loads the project preview bridge.";
  });
  return details;
}

function renderLivePreviews(decisions, handoffUrls) {
  const grid = $("live-grid");
  grid.replaceChildren();
  const eligible = handoffUrls.map((url, index) => ({ url, index })).filter(item => item.url);
  const previewed = eligible.slice(0, MAX_LIVE_PREVIEWS);
  const run = { source: source.value, decisions, expected: previewed.length, entries: new Map(), failed: false };
  liveRun = run;
  updateRunRecord();
  $("live-count").textContent = eligible.length ?
    `${Math.min(eligible.length, MAX_LIVE_PREVIEWS)} of ${eligible.length} eligible engram${eligible.length === 1 ? "" : "s"}` :
    "No eligible engrams";
  if (!eligible.length) {
    grid.append(element("p", "live-empty", "Compile an engram with a representable purpose, value, and declared numbers to see a browser gate here."));
    return;
  }
  for (const { url, index } of previewed) {
    const decision = decisions[index];
    const panel = document.createElement("article");
    panel.className = "live-panel";
    panel.dataset.state = "loading";
    const title = element("h3", "", decision.identifier || "Unnamed engram");
    const top = document.createElement("div");
    top.className = "live-panel-top";
    const verdict = element("strong", "gate-verdict", "CONNECTING");
    top.append(title, verdict);
    const frame = document.createElement("div");
    frame.className = "live-frame";
    frame.append(element("span", "live-frame-label", "SAMPLE INTERFACE · ENFORCE / CLOSED"));
    const surface = document.createElement("div");
    surface.className = "live-surface";
    const absence = element("p", "live-absence", "Connecting to the project browser gate…");
    surface.append(absence);
    frame.append(surface);
    const status = element("p", "live-event", "Waiting for aml-decision…");
    status.setAttribute("role", "status");
    const trace = document.createElement("ol");
    trace.className = "gate-trace";
    trace.setAttribute("aria-label", "Decision trace");
    const traceStep = (label, value) => {
      const item = document.createElement("li");
      item.append(element("span", "trace-label", label), element("strong", "trace-value", value));
      trace.append(item);
      return item.lastElementChild;
    };
    traceStep("01 / DECLARED", `cost ${decision.attention_cost} · value ${decision.restoration_value}`);
    traceStep("02 / COMPILER", decision.render_allowed === true ? "ALLOW" : "SUPPRESS");
    const browserStep = traceStep("03 / BROWSER", "WAITING");
    panel.append(top, frame, status, trace);
    grid.append(panel);
    if (bridgeState !== "ready") {
      if (bridgeState === "unavailable") {
        panel.dataset.state = "unavailable";
        verdict.textContent = "UNAVAILABLE";
        browserStep.textContent = "NO EVENT";
        absence.textContent = "Browser gate unavailable here.";
        status.textContent = "No browser decision was emitted.";
        run.failed = true;
        updateRunRecord();
      }
      continue;
    }
    let declaration;
    try { declaration = parseSharedIntegration(url); }
    catch { panel.dataset.state = "unavailable"; verdict.textContent = "UNAVAILABLE"; browserStep.textContent = "NO EVENT"; absence.textContent = "This declaration cannot be previewed."; run.failed = true; updateRunRecord(); continue; }
    const handoff = takeGate(declaration, url);
    panel.append(handoff);
    const gate = document.createElement("aml-gate");
    gate.setAttribute("purpose", declaration.purpose);
    gate.setAttribute("content", "Playground example");
    gate.setAttribute("attention-cost", String(declaration.attention));
    gate.setAttribute("restoration-value", String(declaration.restoration));
    gate.setAttribute("mode", "enforce");
    gate.setAttribute("failure-mode", "closed");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = declaration.label;
    gate.append(button);
    let observed = false;
    gate.addEventListener("aml-decision", event => {
      if (liveRun !== run) return;
      observed = true;
      const valid = verifiedGateEvent(event.detail, decision, declaration, gate.hidden);
      if (valid) {
        run.entries.set(index, {
          index, declaration, hidden: gate.hidden, observedAt: new Date().toISOString(),
          detail: {
            ok: event.detail.ok, purpose: event.detail.purpose,
            attention_cost: event.detail.attention_cost, restoration_value: event.detail.restoration_value,
            deployment_mode: event.detail.deployment_mode, failure_mode: event.detail.failure_mode,
            render_allowed: event.detail.render_allowed, effective_rendered: event.detail.effective_rendered
          }
        });
      } else {
        run.entries.delete(index);
        run.failed = true;
      }
      updateRunRecord();
      panel.dataset.state = valid ? event.detail.render_allowed ? "allow" : "suppress" : "mismatch";
      verdict.textContent = valid ? event.detail.render_allowed ? "ALLOW" : "SUPPRESS" : "MISMATCH";
      handoff.hidden = !valid;
      trace.dataset.state = valid ? "matched" : "mismatch";
      browserStep.textContent = valid ? event.detail.effective_rendered ? "VISIBLE · MATCHED" : "WITHHELD · MATCHED" : "MISMATCH · CLOSED";
      if (!valid) gate.hidden = true;
      absence.hidden = valid && event.detail.effective_rendered;
      absence.textContent = valid ? "Element withheld by the browser gate" :
        "The browser event did not match this compiler decision.";
      status.textContent = valid ?
        `aml-decision · ${event.detail.render_allowed ? "allow · visible" : "suppress · withheld"}` :
        "MISMATCH · do not rely on this preview";
    });
    try { surface.prepend(gate); }
    catch { /* The preview stays unavailable if a custom-element reaction fails. */ }
    if (!observed) {
      gate.hidden = true;
      panel.dataset.state = "unavailable";
      verdict.textContent = "UNAVAILABLE";
      browserStep.textContent = "NO EVENT";
      absence.textContent = "The browser gate did not emit a usable decision.";
      status.textContent = "No browser decision was emitted.";
      run.failed = true;
      updateRunRecord();
    }
  }
  if (eligible.length > MAX_LIVE_PREVIEWS) {
    grid.append(element("p", "live-empty", "Showing the first six eligible engrams. Each remaining decision is still listed above with its individual Studio link."));
  }
}

function showRaw() {
  if (!result) { output.textContent = "Compile a program to inspect the engine output."; return; }
  const value = view === "amt" ? result.amt : view === "ast" ? result.ast :
    view === "tokens" ? result.tokens : result.renderDecisions;
  output.textContent = JSON.stringify(value, null, 2);
}

function syncExperiment() {
  const restoration = comparisonRestoration(source.value);
  const experiment = $("experiment");
  experiment.hidden = restoration === null;
  if (restoration === null) return;
  $("claim-dial").value = String(restoration);
  $("claim-dial").style.setProperty("--fill", `${restoration * 10}%`);
  $("claim-value").textContent = String(restoration);
  $("claim-rule").textContent = restoration >= 5 ? "Meets declared attention 5" : "Below declared attention 5";
  $("claim-rule").dataset.state = restoration >= 5 ? "allow" : "suppress";
}

function compile() {
  syncExperiment();
  try {
    result = compileSourceBrowser(source.value);
    const decisions = result.renderDecisions;
    const allowed = decisions.filter(item => item.render_allowed === true).length;
    const suppressed = decisions.length - allowed;
    $("source-status").textContent = `VALID · ${result.tokens.length} tokens · ${decisions.length} decision(s)`;
    $("source-status").dataset.tone = "ok";
    $("summary").textContent = decisions.length ?
      `${allowed} allowed · ${suppressed} suppressed` : "Compiled · no gate-bound nodes";
    $("summary").dataset.tone = suppressed ? "suppress" : decisions.length ? "allow" : "neutral";
    $("decision-status").textContent = "Compiled in this browser with the project engine. The raw decision includes a generated timestamp.";
    const handoffUrls = studioHandoffUrls(result, location.href);
    renderCards(decisions, handoffUrls);
    renderLivePreviews(decisions, handoffUrls);
    showRaw();
  } catch (error) {
    result = null;
    clearRunRecord("Fix the source and compile before recording a run.");
    $("source-status").textContent = "INVALID AML · " + error.message;
    $("source-status").dataset.tone = "error";
    $("summary").textContent = "Fix the source and compile again";
    $("summary").dataset.tone = "error";
    $("decision-cards").replaceChildren(element("p", "empty", error.message));
    $("decision-status").textContent = "No decision was produced from this source.";
    $("live-grid").replaceChildren(element("p", "live-empty", "Fix the source and compile to see a browser gate."));
    $("live-count").textContent = "Awaiting valid source";
    showRaw();
  }
}

$("compile").addEventListener("click", compile);
$("claim-dial").addEventListener("input", event => {
  if (comparisonRestoration(source.value) === null) return;
  source.value = comparisonSample(Number(event.target.value));
  compile();
});
$("claim-reset").addEventListener("click", () => {
  source.value = comparisonSample();
  compile();
});
document.querySelectorAll("[data-preset]").forEach(button => button.addEventListener("click", () => {
  source.value = button.dataset.preset === "compare" ? comparisonSample() : sample(Number(button.dataset.preset));
  compile();
}));
source.addEventListener("input", () => {
  result = null;
  clearRunRecord("Source changed. Compile again to record the new run.");
  syncExperiment();
  $("source-status").textContent = "Source changed · compile to update the report.";
  $("source-status").dataset.tone = "neutral";
  $("summary").textContent = "Awaiting compile";
  $("summary").dataset.tone = "neutral";
  $("decision-cards").replaceChildren();
  $("decision-status").textContent = "The previous result was cleared.";
  $("live-grid").replaceChildren(element("p", "live-empty", "Compile the edited source to update the browser preview."));
  $("live-count").textContent = "Awaiting compile";
  $("share-url").hidden = true;
  showRaw();
});
source.addEventListener("keydown", event => {
  if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) { event.preventDefault(); compile(); }
});
document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => {
  view = button.dataset.view;
  document.querySelectorAll("[data-view]").forEach(tab =>
    tab.setAttribute("aria-pressed", String(tab === button)));
  showRaw();
}));

$("download-record").addEventListener("click", async () => {
  const run = liveRun;
  if (!run || run.failed || !run.expected || run.entries.size !== run.expected || source.value !== run.source) return;
  $("download-record").disabled = true;
  try {
    const record = await createLocalRunRecord({
      source: run.source, decisions: run.decisions,
      entries: [...run.entries.values()].sort((a, b) => a.index - b.index), pageUrl: location.href
    });
    if (liveRun !== run || source.value !== run.source) return;
    const fileUrl = URL.createObjectURL(new Blob([JSON.stringify(record, null, 2) + "\n"], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = fileUrl;
    link.download = "aml-local-run.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(fileUrl), 60_000);
    $("record-status").textContent = `Local run downloaded. Source SHA-256 starts ${record.source_sha256.slice(0, 12)}. Review the source before sharing.`;
  } catch {
    if (liveRun === run) $("record-status").textContent = "This browser could not build the local run record.";
  } finally {
    if (liveRun === run) $("download-record").disabled =
      run.failed || run.entries.size !== run.expected || source.value !== run.source;
  }
});

$("share").addEventListener("click", async () => {
  let url;
  try { url = playgroundShareUrl(source.value, location.href); }
  catch (error) { $("share-status").textContent = error.message; return; }
  $("share-url").value = url;
  $("share-url").hidden = false;
  try {
    await navigator.clipboard.writeText(url);
    $("share-status").textContent = "Source link copied. You can also select it below. Do not share secrets in source.";
  } catch {
    $("share-url").focus();
    $("share-url").select();
    $("share-status").textContent = "Clipboard unavailable. Copy the selected link below. Do not share secrets in source.";
  }
});

try {
  const shared = parsePlaygroundShare(location.href);
  const comparison = new URL(location.href).searchParams.get("example") === "compare";
  source.value = shared ?? (comparison ? comparisonSample() : sample(1));
  if (shared) $("share-status").textContent = "Shared program restored. Edit and compile to test another idea.";
  else if (comparison) $("share-status").textContent = "Two-gate comparison loaded. Edit and compile to try your own.";
} catch {
  source.value = sample(1);
  $("share-status").textContent = "That source link is invalid. The default example is ready.";
}
compile();
try {
  await import("./aml-gate.js");
  bridgeState = "ready";
} catch {
  bridgeState = "unavailable";
}
if (result) renderLivePreviews(result.renderDecisions, studioHandoffUrls(result, location.href));
