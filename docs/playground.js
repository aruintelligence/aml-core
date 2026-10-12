import { compileSourceBrowser } from "./aml-browser.js";
import { parsePlaygroundShare, playgroundShareUrl } from "./playground-core.js";

const $ = id => document.getElementById(id);
const source = $("source");
const output = $("output");
let result = null;
let view = "decisions";

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

function renderCards(decisions) {
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
    list.append(card);
  }
}

function showRaw() {
  if (!result) { output.textContent = "Compile a program to inspect the engine output."; return; }
  const value = view === "amt" ? result.amt : view === "ast" ? result.ast :
    view === "tokens" ? result.tokens : result.renderDecisions;
  output.textContent = JSON.stringify(value, null, 2);
}

function compile() {
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
    renderCards(decisions);
    showRaw();
  } catch (error) {
    result = null;
    $("source-status").textContent = "INVALID AML · " + error.message;
    $("source-status").dataset.tone = "error";
    $("summary").textContent = "Fix the source and compile again";
    $("summary").dataset.tone = "error";
    $("decision-cards").replaceChildren(element("p", "empty", error.message));
    $("decision-status").textContent = "No decision was produced from this source.";
    showRaw();
  }
}

$("compile").addEventListener("click", compile);
document.querySelectorAll("[data-preset]").forEach(button => button.addEventListener("click", () => {
  source.value = sample(Number(button.dataset.preset));
  compile();
}));
source.addEventListener("input", () => {
  result = null;
  $("source-status").textContent = "Source changed · compile to update the report.";
  $("source-status").dataset.tone = "neutral";
  $("summary").textContent = "Awaiting compile";
  $("summary").dataset.tone = "neutral";
  $("decision-cards").replaceChildren();
  $("decision-status").textContent = "The previous result was cleared.";
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
  source.value = shared ?? sample(1);
  if (shared) $("share-status").textContent = "Shared program restored. Edit and compile to test another idea.";
} catch {
  source.value = sample(1);
  $("share-status").textContent = "That source link is invalid. The default example is ready.";
}
compile();
