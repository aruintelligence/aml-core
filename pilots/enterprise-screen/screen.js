const output = document.querySelector("#output");
const placeholder = document.querySelector("#placeholder");
const status = document.querySelector("#status");
const receipt = document.querySelector("#receipt");
let sequence = 0;
let inflight;

function clearRegion(message) {
  output.hidden = true;
  output.removeAttribute("srcdoc");
  placeholder.hidden = false;
  placeholder.textContent = message;
  receipt.textContent = "—";
}

async function evaluate(fixture) {
  const current = ++sequence;
  inflight?.abort();
  const controller = new AbortController();
  inflight = controller;
  clearRegion("Checking the proposed interface…");
  status.textContent = "Verifying signed decision…";
  status.dataset.state = "pending";
  try {
    const response = await fetch("/api/evaluate", { method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ fixture }), signal: controller.signal });
    if (!response.ok) throw new Error("host unavailable");
    const result = await response.json();
    if (current !== sequence) return;
    if (result.decision === "allow" && typeof result.html === "string") {
      // The frame has no allow-scripts, allow-same-origin, forms, or navigation powers.
      output.srcdoc = result.html;
      placeholder.hidden = true;
      output.hidden = false;
      status.textContent = "ALLOW · verified receipt; HTML handed to isolated frame";
      status.dataset.state = "allow";
    } else {
      clearRegion("Suppressed. No proposal HTML was handed to the display frame.");
      status.textContent = `BLOCKED · ${result.reason || "unavailable"}`;
      status.dataset.state = "blocked";
    }
    receipt.textContent = result.receipt_sha256 || "—";
  } catch {
    if (current !== sequence) return;
    clearRegion("Evaluation unavailable. The guarded region stays empty.");
    status.textContent = "BLOCKED · host unavailable";
    status.dataset.state = "blocked";
  } finally {
    if (current === sequence) inflight = undefined;
  }
}

document.querySelectorAll("[data-fixture]").forEach(button => {
  button.addEventListener("click", () => evaluate(button.dataset.fixture));
});
