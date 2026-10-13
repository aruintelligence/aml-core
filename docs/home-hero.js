// The homepage uses the same project-authored action preview as First Contact,
// and an actual <aml-gate> decision event for the interface preview.
// Neither surface dispatches a tool or measures a person's wellbeing.
import { firstRunAction } from "./first-run.js?v=home-real-1";

const $ = id => document.getElementById(id);
let boundary = "action";
let recipient = "outside";
let restoration = 1;
let actionGeneration = 0;
let bridgeReady = false;

function selectButton(selector, key, value) {
  document.querySelectorAll(selector).forEach(button =>
    button.setAttribute("aria-pressed", String(button.dataset[key] === value)));
}

function showTrace(result) {
  $("action-trace").dataset.result = result;
  $("trace-decision").textContent = result === "blocked" ? "Blocked" :
    result === "approval" ? "Needs approval" : result === "pending" ? "Calculating" : "Unavailable";
  $("trace-dispatch").textContent = result === "blocked" ? "Stopped before tool" :
    result === "approval" ? "Awaits real host" : "Not connected";
}

async function showAction() {
  const turn = ++actionGeneration;
  $("action-recipient").textContent = recipient === "team" ? "team@example.test" : "outsider@example.test";
  $("action-target").classList.toggle("approved", recipient === "team");
  selectButton("[data-action-destination]", "actionDestination", recipient);
  $("action-verdict").classList.remove("allow", "approval");
  $("action-verdict").querySelector("strong").textContent = "CALCULATING";
  showTrace("pending");
  $("hero-digest").textContent = "Calculating canonical proposal…";
  $("hero-vector").textContent = "Project vector self-check pending.";
  $("action-count").textContent = "No tool callback is connected to this page.";
  $("action-link").href = recipient === "team" ? "action-lab.html?scenario=send" : "action-lab.html?scenario=changed";
  if (boundary === "action") $("hero-note").textContent =
    "Calculating the project action plan. No tool runs, no message is sent, and no person is asked to approve.";

  try {
    const result = await firstRunAction(recipient, globalThis.crypto?.subtle);
    if (turn !== actionGeneration) return;
    const matches = result.project_vector_matches;
    const approval = result.decision === "requires_approval";
    $("action-verdict").classList.toggle("approval", matches && approval);
    $("action-verdict").querySelector("strong").textContent = !matches ? "RECHECK" :
      approval ? "APPROVAL REQUIRED" : result.decision === "deny" ? "BLOCKED" : "RECHECK";
    showTrace(!matches ? "unavailable" : approval ? "approval" : result.decision === "deny" ? "blocked" : "unavailable");
    $("action-count").textContent = !matches ? "Project vector mismatch. Inspect the source before relying on this preview." :
      approval ? "The route matches. A real host must approve the exact proposal before dispatch." :
      "No exact rule matches this destination; zero tool callbacks.";
    $("hero-digest").textContent = result.proposal_sha256 || "Unavailable";
    $("hero-vector").textContent = matches ?
      "Matches the published project vector · self-check only" : "Project vector mismatch · investigate";
    if (boundary === "action") $("hero-note").textContent = matches ?
      "Project browser planner and vector self-check. No tool runs, no message is sent, and no person is asked to approve." :
      "The project vector did not match. Follow the source link to investigate before relying on this preview.";
  } catch {
    if (turn !== actionGeneration) return;
    $("action-verdict").querySelector("strong").textContent = "UNAVAILABLE";
    showTrace("unavailable");
    $("action-count").textContent = "The browser could not calculate the action plan here.";
    $("hero-digest").textContent = "Unavailable";
    $("hero-vector").textContent = "No project vector self-check completed.";
    if (boundary === "action") $("hero-note").textContent =
      "Action calculation unavailable in this browser. Follow the source lab for the project cases.";
  }
}

function showInterface() {
  $("hero-value").textContent = String(restoration);
  selectButton("[data-hero-value]", "heroValue", String(restoration));
  $("hero-proof").href = `proof.html?attention=5&restoration=${restoration}&lang=en`;
  $("hero-verdict").classList.remove("allow");
  $("hero-verdict").querySelector("strong").textContent = bridgeReady ? "CALCULATING" : "LOADING";
  $("hero-gate-slot").replaceChildren();
  $("hero-gate-placeholder").hidden = false;
  $("hero-gate-placeholder").textContent = bridgeReady ? "Evaluating the declared element…" : "Connecting to the project browser gate…";
  if (boundary === "interface") $("hero-note").textContent = bridgeReady ?
    "Evaluating declared inputs in the project browser gate. These values are not objective measurements of a person." :
    "Connecting to the project browser gate. These values are not objective measurements of a person.";
  if (!bridgeReady) return;

  const gate = document.createElement("aml-gate");
  gate.setAttribute("purpose", "Review an offer without urgency");
  gate.setAttribute("attention-cost", "5");
  gate.setAttribute("restoration-value", String(restoration));
  gate.setAttribute("mode", "enforce");
  gate.setAttribute("failure-mode", "closed");
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Review the offer";
  gate.append(button);
  gate.addEventListener("aml-decision", event => {
    const detail = event.detail;
    const allowed = detail.ok && detail.render_allowed;
    $("hero-verdict").classList.toggle("allow", allowed);
    $("hero-verdict").querySelector("strong").textContent = !detail.ok ? "UNAVAILABLE" : allowed ? "ALLOW" : "SUPPRESS";
    $("hero-gate-placeholder").hidden = detail.ok && detail.effective_rendered;
    $("hero-gate-placeholder").textContent = !detail.ok ? "Gate evaluation unavailable." : "Element withheld by the browser gate";
    $("hero-gate-event").textContent = detail.ok ?
      `aml-decision · ${detail.render_allowed ? "allow" : "suppress"} · ${detail.effective_rendered ? "visible" : "hidden"}` :
      "No successful aml-decision";
    if (boundary === "interface") $("hero-note").textContent =
      "The project browser gate evaluates declared inputs and emits an event. These values are not objective measurements of a person.";
  });
  $("hero-gate-slot").append(gate);
}

function showBoundary() {
  const action = boundary === "action";
  $("action-preview").hidden = !action;
  $("interface-preview").hidden = action;
  selectButton("[data-boundary]", "boundary", boundary);
  $("hero-equation").textContent = action ?
    "proposal → SHA-256 → exact host rule → plan" :
    "declared values → browser gate → decision event";
  if (action) showAction(); else showInterface();
}

document.querySelectorAll("[data-boundary]").forEach(button =>
  button.addEventListener("click", () => { boundary = button.dataset.boundary; showBoundary(); }));
document.querySelectorAll("[data-action-destination]").forEach(button =>
  button.addEventListener("click", () => { recipient = button.dataset.actionDestination; showAction(); }));
document.querySelectorAll("[data-hero-value]").forEach(button =>
  button.addEventListener("click", () => { restoration = Number(button.dataset.heroValue); showInterface(); }));

showBoundary();
try {
  await import("./aml-gate.js");
  bridgeReady = true;
  if (boundary === "interface") showInterface();
} catch {
  bridgeReady = false;
  $("hero-gate-placeholder").textContent = "Browser gate unavailable here. Open the interface proof to inspect the source.";
  $("hero-gate-event").textContent = "No successful aml-decision";
  if (boundary === "interface") {
    $("hero-verdict").querySelector("strong").textContent = "UNAVAILABLE";
    $("hero-note").textContent = "Browser gate unavailable here. Follow the interface proof for the project cases.";
  }
}
