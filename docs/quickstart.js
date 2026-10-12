import { downloadablePage, integrationSnippet, normalizeIntegration, parseSharedIntegration, shareableStudioUrl } from "./quickstart-core.js?v=unicode-share-2";

const $ = id => document.getElementById(id);
const params = new URLSearchParams(location.search);
for (const name of ["attention", "restoration"]) {
  const value = params.get(name);
  if (value !== null && /^(10|[0-9])$/.test(value)) $(name).value = value;
}
let sharedState = "";
try {
  const shared = parseSharedIntegration(location.href);
  if (shared) {
    for (const name of ["purpose", "label", "attention", "restoration"]) $(name).value = shared[name];
    document.querySelector(`input[name="mode"][value="${shared.mode}"]`).checked = true;
    sharedState = "Shared configuration restored. Change any field to explore a different result.";
    $("studio").scrollIntoView();
  }
} catch {
  sharedState = "That shared configuration is invalid. The default example is ready to explore.";
}

let bridgeReady = false;
let current = null;

function showError(message) {
  $("decision").dataset.tone = "loading";
  $("decision-word").textContent = "CHECK INPUT";
  $("decision-description").textContent = message;
  $("trace").textContent = "No gate decision was emitted.";
  $("preview-slot").replaceChildren();
  $("absence").hidden = true;
}

function showDecision(detail) {
  if (!detail.ok) {
    showError(detail.error || "The browser gate could not evaluate this declaration.");
    return;
  }
  const allowed = detail.render_allowed;
  $("decision").dataset.tone = allowed ? "allow" : "suppress";
  $("decision-word").textContent = allowed ? "ALLOW" : "SUPPRESS";
  $("decision-description").textContent = allowed ?
    "Declared restoration meets or exceeds declared attention cost." :
    detail.deployment_mode === "shadow" ?
      "The policy would suppress this element. Shadow mode keeps it visible for observation." :
      "Declared restoration is below attention cost. Enforce mode hides the element.";
  $("absence").hidden = detail.effective_rendered;
  $("trace").textContent = JSON.stringify({
    render_allowed: detail.render_allowed,
    effective_rendered: detail.effective_rendered,
    deployment_mode: detail.deployment_mode,
    failure_mode: detail.failure_mode,
    attention_cost: detail.attention_cost,
    restoration_value: detail.restoration_value
  }, null, 2);
}

function update() {
  $("attention-output").textContent = $("attention").value;
  $("restoration-output").textContent = $("restoration").value;
  $("share-url").hidden = true;
  if ($("takeaway-status").textContent.startsWith("Scenario link copied.")) {
    $("takeaway-status").textContent = "Declaration changed. Copy a new link to share these values.";
  }
  try {
    current = normalizeIntegration({
      purpose: $("purpose").value,
      label: $("label").value,
      attention: $("attention").value,
      restoration: $("restoration").value,
      mode: document.querySelector('input[name="mode"]:checked')?.value
    });
  } catch (error) {
    current = null;
    $("snippet").textContent = "Add a purpose and button label to continue.";
    $("copy").disabled = $("download").disabled = $("share").disabled = true;
    showError(error.message);
    return;
  }

  $("copy").disabled = $("download").disabled = $("share").disabled = false;
  $("snippet").textContent = integrationSnippet(current);
  if (!bridgeReady) return;

  // Construct a fresh, real custom element for each input. Attributes are complete
  // before connection, so the displayed event corresponds to just one declaration.
  const gate = document.createElement("aml-gate");
  gate.setAttribute("purpose", current.purpose);
  gate.setAttribute("attention-cost", String(current.attention));
  gate.setAttribute("restoration-value", String(current.restoration));
  gate.setAttribute("mode", current.mode);
  gate.setAttribute("failure-mode", "closed");
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = current.label;
  gate.append(button);
  gate.addEventListener("aml-decision", event => showDecision(event.detail));
  $("absence").hidden = true;
  $("preview-slot").replaceChildren(gate);
}

for (const id of ["purpose", "label", "attention", "restoration"]) $(id).addEventListener("input", update);
document.querySelectorAll('input[name="mode"]').forEach(input => input.addEventListener("change", update));

$("copy").addEventListener("click", async () => {
  if (!current) return;
  try {
    await navigator.clipboard.writeText(integrationSnippet(current));
    $("takeaway-status").textContent = "HTML copied. The bridge URL points to the current project preview; review and pin assets before deployment.";
  } catch {
    $("takeaway-status").textContent = "Clipboard unavailable. Select the HTML above to copy it.";
  }
});

$("share").addEventListener("click", async () => {
  if (!current) return;
  const url = shareableStudioUrl(current, location.href);
  try {
    await navigator.clipboard.writeText(url);
    $("share-url").hidden = true;
    $("takeaway-status").textContent = "Scenario link copied. It restores this exact declaration in the Studio.";
  } catch {
    $("share-url").hidden = false;
    $("share-url").value = url;
    $("share-url").focus();
    $("share-url").select();
    $("takeaway-status").textContent = "Clipboard unavailable. Copy the selected scenario link below.";
  }
});

$("download").addEventListener("click", () => {
  if (!current) return;
  const file = new Blob([downloadablePage(current)], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(file);
  const link = document.createElement("a");
  link.href = url;
  link.download = "my-aml-gate.html";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
  $("takeaway-status").textContent = "Page downloaded. Open it with internet access; it loads the project preview bridge from GitHub Pages.";
});

update();
if (sharedState) $("takeaway-status").textContent = sharedState;
try {
  await import("./aml-gate.js");
  bridgeReady = true;
  update();
} catch {
  $("decision").dataset.tone = "loading";
  $("decision-word").textContent = "UNAVAILABLE";
  $("decision-description").textContent = "The project browser bridge could not load here. Try the hosted page again or inspect the source.";
  $("trace").textContent = "No browser decision was emitted.";
}
