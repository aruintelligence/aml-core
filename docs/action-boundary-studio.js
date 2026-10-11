import { planPreview } from "./action-lab-core.js?v=one-use-grant-1";

const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
  resource: "team@example.test", purpose: "Send a status update",
  arguments: { to: "team@example.test", subject: "Update", body: "The build passed." } };
const policy = { protocol: "aml-action-policy/1", rules: [
  { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true },
  { tool: "fetch_record", effect: "read", resource: "record:42", requires_approval: false }
] };
const presets = {
  approval: () => [proposal, policy],
  destination: () => [{ ...proposal, resource: "outsider@example.test",
    arguments: { ...proposal.arguments, to: "outsider@example.test" } }, policy],
  body: () => [{ ...proposal, arguments: { ...proposal.arguments, body: "Different text" } }, policy],
  read: () => [{ ...proposal, tool: "fetch_record", effect: "read", resource: "record:42",
    purpose: "Inspect a record", arguments: { id: 42 } }, policy],
  ambiguous: () => [proposal, { ...policy, rules: [...policy.rules, { ...policy.rules[0] }] }]
};
const $ = id => document.getElementById(id);
let current = null;
let generation = 0;
const planKeys = ["protocol", "proposal_sha256", "decision", "reason"];
const LIMITS = "Calculation consistency only. No trusted policy, identity, approval, live tool, or delivery proof.";

function parse(id) {
  try { return JSON.parse($(id).value); }
  catch (error) { $(id + "-error").textContent = "Invalid JSON: " + error.message; return undefined; }
}

function bundle() {
  if (!current) return null;
  const { proposal: input, policy: rules, plan } = current;
  return { protocol: "aml-action-studio-bundle/1", source: "project-authored local browser preview",
    proposal: input, policy: rules, plan: Object.fromEntries(planKeys.map(key => [key, plan[key]])),
    canonical_proposal_json: plan.canonical_json, limits: LIMITS };
}

async function render() {
  const turn = ++generation;
  $("proposal-error").textContent = "";
  $("policy-error").textContent = "";
  $("export-status").textContent = "";
  const input = parse("proposal");
  const rules = parse("policy");
  if (input === undefined || rules === undefined) {
    current = null;
    $("decision").textContent = "INVALID JSON";
    $("reason").textContent = "Correct the editor error to calculate a plan.";
    $("verdict").className = "verdict deny";
    $("digest").textContent = "No digest calculated";
    $("match").textContent = "No rule comparison";
    $("canonical").textContent = "No canonical proposal";
    $("path-proposal").textContent = "Invalid JSON";
    $("path-policy").textContent = "Waiting for input";
    $("path-decision").textContent = "No plan";
    $("path-decision-card").dataset.state = "deny";
    $("download").disabled = $("copy").disabled = true;
    return;
  }
  const plan = await planPreview(input, rules, crypto.subtle);
  if (turn !== generation) return;
  current = { proposal: input, policy: rules, plan };
  $("download").disabled = $("copy").disabled = false;
  $("decision").textContent = plan.decision.toUpperCase().replaceAll("_", " ");
  $("reason").textContent = plan.reason.replaceAll("_", " ");
  $("verdict").className = "verdict " + plan.decision;
  $("digest").textContent = plan.proposal_sha256 || "No valid proposal digest";
  const matches = Array.isArray(rules?.rules) && input && typeof input === "object" ?
    rules.rules.filter(rule => rule && rule.tool === input.tool && rule.effect === input.effect && rule.resource === input.resource).length : null;
  $("match").textContent = matches === null ? "Invalid policy shape" :
    `${matches} exact ${matches === 1 ? "rule" : "rules"} for tool + effect + resource`;
  $("canonical").textContent = plan.canonical_json || "Unavailable for this proposal";
  $("path-proposal").textContent = plan.proposal_sha256 ? `${String(input.effect).toUpperCase()} · ${String(input.tool)}` : "Invalid proposal";
  $("path-policy").textContent = plan.reason === "ambiguous_policy" ? "Ambiguous rules" :
    plan.reason === "exact_rule" ? "One exact match" : plan.reason === "no_exact_rule" ? "No exact match" : "Invalid input";
  $("path-decision").textContent = $("decision").textContent;
  $("path-decision-card").dataset.state = plan.decision === "requires_approval" ? "approval" : plan.decision;
}

function selectPreset(name) {
  const [input, rules] = presets[name]();
  $("proposal").value = JSON.stringify(input, null, 2);
  $("policy").value = JSON.stringify(rules, null, 2);
  document.querySelectorAll("[data-preset]").forEach(button =>
    button.setAttribute("aria-pressed", String(button.dataset.preset === name)));
  render();
}

document.querySelectorAll("[data-preset]").forEach(button =>
  button.addEventListener("click", () => selectPreset(button.dataset.preset)));
for (const id of ["proposal", "policy"]) $(id).addEventListener("input", () => {
  document.querySelectorAll("[data-preset]").forEach(button => button.setAttribute("aria-pressed", "false"));
  render();
});
$("download").addEventListener("click", () => {
  const data = bundle(); if (!data) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2) + "\n"], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url; link.download = "aml-action-studio-bundle.json";
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  $("export-status").textContent = "Downloaded the current local calculation.";
});
$("copy").addEventListener("click", async () => {
  const data = bundle(); if (!data) return;
  try { await navigator.clipboard.writeText(JSON.stringify(data, null, 2) + "\n");
    $("export-status").textContent = "Copied the current local calculation."; }
  catch { $("export-status").textContent = "Clipboard access was blocked. Use Download JSON."; }
});
selectPreset("approval");
