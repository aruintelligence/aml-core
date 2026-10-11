import { planPreview, rehearse } from "./action-lab-core.js";
import { actionPathStory } from "./action-lab-story.js";

const policy = {
  protocol: "aml-action-policy/1",
  rules: [
    { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true },
    { tool: "fetch_record", effect: "read", resource: "record:42", requires_approval: false }
  ]
};
const cases = {
  send: { tool: "send_message", effect: "send", resource: "team@example.test",
    purpose: "Send a status update", arguments: { subject: "Update", body: "The build passed." } },
  changed: { tool: "send_message", effect: "send", resource: "outsider@example.test",
    purpose: "Send a status update", arguments: { subject: "Update", body: "The build passed." } },
  read: { tool: "fetch_record", effect: "read", resource: "record:42",
    purpose: "Inspect record", arguments: { id: 42 } },
  timeout: { tool: "send_message", effect: "send", resource: "team@example.test",
    purpose: "Send a status update", arguments: { subject: "Update", body: "The build passed." } },
  replay: { tool: "send_message", effect: "send", resource: "team@example.test",
    purpose: "Send a status update", arguments: { subject: "Update", body: "The build passed." } }
};
const $ = id => document.getElementById(id);
const form = $("proposal");
let scenario = "send";
let approvedDigest = null;
let grantConsumed = false;
let outcome = null;
let latest = null;
let generation = 0;
const input = name => form.elements.namedItem(name);

function readProposal() {
  let args;
  try { args = JSON.parse(input("arguments").value); }
  catch { throw new Error("arguments_must_be_json"); }
  if (args === null || typeof args !== "object" || Array.isArray(args)) {
    throw new Error("arguments_must_be_object");
  }
  return { protocol: "aml-proposed-action/1", tool: input("tool").value,
    effect: input("effect").value, resource: input("resource").value,
    purpose: input("purpose").value, arguments: args };
}

async function render() {
  const turn = ++generation;
  let proposal, plan;
  try {
    proposal = readProposal();
    plan = await planPreview(proposal, policy, crypto.subtle);
  } catch (error) {
    plan = { protocol: "aml-action-plan/1", proposal_sha256: null,
      decision: "deny", reason: error.message, canonical_json: null };
  }
  if (turn !== generation) return; // Discard an older asynchronous digest.
  latest = { proposal, plan };
  const approved = Boolean(approvedDigest && approvedDigest === plan.proposal_sha256);
  $("decision").textContent = plan.decision.toUpperCase().replaceAll("_", " ");
  $("decision").className = "badge " + plan.decision;
  $("reason").textContent = plan.reason === "exact_rule" ?
    "One exact host rule matches this tool, effect, and resource." :
    "Reason: " + plan.reason.replaceAll("_", " ");
  $("digest").textContent = plan.proposal_sha256 || "No valid proposal digest";
  $("approve").disabled = plan.decision !== "requires_approval";
  $("approval").textContent = approved && grantConsumed ?
    "Simulated one-use grant spent. Re-approve to try again." :
    approved ? "Simulated approval matches this exact digest." :
    approvedDigest ? "Previous simulated approval is stale for this proposal." :
      "No simulated approval recorded.";
  $("outcome").textContent = outcome ? outcome.outcome.toUpperCase().replaceAll("_", " ") : "NOT ATTEMPTED";
  $("outcome").className = "badge " + (outcome?.outcome || "");
  const story = actionPathStory(proposal, plan, approvedDigest, outcome, grantConsumed);
  for (const key of ["proposal", "policy", "approval", "receipt"]) {
    const card = $("path-" + key);
    card.dataset.tone = story[key].tone;
    $("path-" + key + "-value").textContent = story[key].value;
    $("path-" + key + "-detail").textContent = story[key].detail;
  }
  const report = { protocol: "aml-action-lab-report/1", provenance: "project-authored browser simulation",
    proposal: proposal || null, plan, simulated_approval_matches: approved,
    simulated_one_use_grant_spent: scenario === "replay" ? grantConsumed : null,
    simulation: outcome, canonical_proposal_json: plan.canonical_json,
    limits: "No live tool, authenticated approver, external delivery, or execution proof." };
  $("report").textContent = JSON.stringify(report, null, 2);
}

function selectCase(name) {
  scenario = name;
  approvedDigest = null;
  grantConsumed = false;
  outcome = null;
  const selected = cases[name];
  for (const key of ["tool", "effect", "resource", "purpose"]) input(key).value = selected[key];
  input("arguments").value = JSON.stringify(selected.arguments, null, 2);
  document.querySelectorAll("[data-case]").forEach(button => {
    button.setAttribute("aria-pressed", String(button.dataset.case === name));
  });
  render();
}

form.addEventListener("submit", event => event.preventDefault());
form.addEventListener("input", () => { outcome = null; render(); });
document.querySelectorAll("[data-case]").forEach(button =>
  button.addEventListener("click", () => selectCase(button.dataset.case)));
$("approve").addEventListener("click", async () => {
  // Recompute the current proposal before storing a demonstration-only digest.
  await render();
  if (latest.plan.decision === "requires_approval") {
    approvedDigest = latest.plan.proposal_sha256;
    grantConsumed = false;
    outcome = null;
    await render();
  }
});
$("dispatch").addEventListener("click", async () => {
  await render();
  const oneUse = scenario === "replay";
  const wasConsumed = oneUse && grantConsumed;
  outcome = rehearse(latest.plan, approvedDigest, scenario === "timeout", wasConsumed);
  if (oneUse && !wasConsumed && outcome.outcome === "would_dispatch") grantConsumed = true;
  await render();
});
$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("report").textContent);
    $("approval").textContent = "Local report copied. It includes your entered arguments.";
  } catch {
    $("approval").textContent = "Clipboard unavailable. Select the report text to copy it.";
  }
});
$("policy").textContent = JSON.stringify(policy, null, 2);
const requestedScenario = new URLSearchParams(window.location.search).get("scenario");
selectCase(Object.hasOwn(cases, requestedScenario) ? requestedScenario : "send");

