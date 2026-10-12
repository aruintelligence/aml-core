// The action calculation uses the same project-authored planner as the Action Lab.
// This page does not grant approval, dispatch a tool, or issue an execution receipt.
import { planPreview } from "./action-lab-core.js";

export const firstRunPolicy = {
  protocol: "aml-action-policy/1",
  rules: [{ tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true }]
};

const publishedVectors = {
  team: { sha256: "a8a184bda13626554b6bf9494f8cd2dd526f4ea16baf58d9845b16e3e3be3332",
    decision: "requires_approval", reason: "exact_rule" },
  outside: { sha256: "d02df0aafadc6b9db6744083baac970afac76c0510b05de60b02d80172749d53",
    decision: "deny", reason: "no_exact_rule" }
};

export function firstRunProposal(recipient) {
  if (recipient !== "team" && recipient !== "outside") throw new RangeError("Unknown first-run scenario");
  return {
    protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
    resource: recipient === "team" ? "team@example.test" : "outsider@example.test",
    purpose: "Status ✓", arguments: {
      subject: "Update", body: "The build passed.", metadata: { z: 2, a: ["é", true, null] }
    }
  };
}

export async function firstRunAction(recipient, subtle) {
  if (!subtle || typeof subtle.digest !== "function") throw new Error("browser_crypto_unavailable");
  const proposal = firstRunProposal(recipient);
  const plan = await planPreview(proposal, firstRunPolicy, subtle);
  const expected = publishedVectors[recipient];
  return {
    proposed: `send_message → ${proposal.resource}`,
    policy: "send_message → team@example.test; approval required",
    decision: plan.decision, reason: plan.reason,
    proposal_sha256: plan.proposal_sha256,
    canonical_json: plan.canonical_json,
    published_vector_sha256: expected.sha256,
    project_vector_matches: plan.proposal_sha256 === expected.sha256 &&
      plan.decision === expected.decision && plan.reason === expected.reason,
    tool_callbacks: 0
  };
}

export function renderDecision(attention, restoration) {
  if (![attention, restoration].every(value => Number.isInteger(value) && value >= 0 && value <= 10)) {
    throw new RangeError("Declared values must be integers from 0 through 10");
  }
  return {
    proposed: "render a conversion prompt",
    policy: "restoration_value >= attention_cost",
    attention_cost: attention,
    restoration_value: restoration,
    decision: restoration >= attention ? "allow" : "suppress",
    reason: restoration >= attention ? "declared_value_meets_cost" : "declared_value_below_cost"
  };
}

export function buildNextStep(mode, attention, restoration, recipient = "outside") {
  if (mode === "action") {
    if (recipient !== "team" && recipient !== "outside") throw new RangeError("Unknown first-run recipient");
    return {
    title: "Wrap one host-owned tool.",
    description: "Run a simulated local callback, compare the exact route with a changed destination, then wire your own policy and approval in the host.",
    href: `agent-start.html?recipient=${recipient}`,
    label: "Build a guarded function tool ↗",
    hint: "node pilots/action-boundary/guarded-tool-demo.mjs"
  };
  }
  if (mode === "render") {
    renderDecision(attention, restoration); // Bound values before putting them in a URL.
    return {
      title: "Put a gate around one element.",
      description: "Shape a live browser gate with these declared values, inspect its event, then download a runnable HTML page.",
      href: `quickstart.html?attention=${attention}&restoration=${restoration}`,
      label: "Build your first gate ↗",
      hint: "One element · no framework migration"
    };
  }
  throw new RangeError("Unknown first-run mode");
}

if (typeof document !== "undefined" && document.getElementById("experience")) {
  const $ = id => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  let mode = params.get("mode") === "render" ? "render" : "action";
  let recipient = params.get("recipient") === "team" ? "team" : "outside";
  const initial = (name, fallback) => {
    const raw = params.get(name);
    if (raw === null || !/^(10|[0-9])$/.test(raw)) return fallback;
    return Number(raw);
  };
  $("attention").value = initial("attention", 5);
  $("restoration").value = initial("restoration", 1);

  let generation = 0;
  async function update() {
    const turn = ++generation;
    const action = mode === "action";
    const attention = Number($("attention").value);
    const restoration = Number($("restoration").value);
    let result;
    try {
      result = action ? await firstRunAction(recipient, globalThis.crypto?.subtle) :
        renderDecision(attention, restoration);
    } catch {
      result = action ? { proposed: `send_message → ${recipient === "team" ? "team" : "outsider"}@example.test`,
        decision: "deny", reason: "browser_crypto_unavailable", proposal_sha256: null,
        project_vector_matches: false, tool_callbacks: 0 } :
        { proposed: "render a conversion prompt", decision: "suppress", reason: "invalid_declared_value" };
    }
    if (turn !== generation) return; // An older asynchronous digest must not overwrite a new input.
    const mismatch = action && !result.project_vector_matches;
    const tone = action ? (result.decision === "deny" || mismatch ? "stop" : "hold") :
      (result.decision === "allow" ? "go" : "stop");

    document.querySelectorAll("[data-mode]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.mode === mode)));
    document.querySelectorAll("[data-recipient]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.recipient === recipient)));
    $("action-controls").hidden = !action;
    $("render-controls").hidden = action;
    $("screen-preview").hidden = action;
    $("experience-title").textContent = action ? "Move the destination." : "Change what reaches the screen.";
    $("instruction").textContent = action ?
      "An agent proposes send_message. The host has one exact rule for the team destination and still requires approval for a matching action." :
      "An app proposes a conversion prompt. The prototype compares two declared values before deciding whether this element may render.";
    $("attention-value").textContent = String(attention);
    $("restoration-value").textContent = String(restoration);
    $("path-proposal").textContent = result.proposed;
    $("path-rule").textContent = action ? "team@example.test only" : "restoration ≥ attention";
    $("path-result").textContent = mismatch ? "VECTOR MISMATCH" : result.decision.replaceAll("_", " ").toUpperCase();
    $("path-result-card").dataset.tone = tone;
    $("orb").dataset.tone = tone;
    $("orb-word").textContent = action ? (mismatch ? "RECHECK" : tone === "stop" ? "BLOCKED" : "HELD") :
      (tone === "go" ? "VISIBLE" : "WITHHELD");
    $("verdict-label").textContent = action ? "ACTION HELD BEFORE DISPATCH" : "INTERFACE RENDER DECISION";
    $("verdict-title").textContent = action ? (mismatch ? "The published vector did not match." : tone === "stop" ? "The route does not match." : "The route matches. Approval is next.") :
      (tone === "go" ? "This element passes the gate." : "This element is suppressed.");
    $("verdict-explanation").textContent = mismatch ?
      "Do not rely on this preview. Open the source vectors and executable lab to investigate the disagreement." : action ? (tone === "stop" ?
      "The exact host rule cannot authorize this destination. The local preview invokes no tool." :
      "An exact rule match still does not dispatch the tool. A real host must approve the exact proposal first.") :
      (tone === "go" ? "Declared restoration meets or exceeds declared attention cost under this prototype rule." :
      "Declared restoration is below declared attention cost under this prototype rule.");
    $("screen-preview").dataset.tone = tone;
    $("screen-title").textContent = tone === "go" ? "Continue with the offer" : "Suppressed by policy";
    $("screen-detail").textContent = tone === "go" ? "A local illustration of an allowed prompt." :
      "The proposed prompt is withheld in this local illustration.";
    $("fingerprint").hidden = !action;
    $("vector-link").hidden = !action;
    $("digest").textContent = result.proposal_sha256 || "Unavailable";
    $("vector-status").textContent = mismatch ? "PROJECT VECTOR MISMATCH · INVESTIGATE" :
      "MATCHES THE PUBLISHED PROJECT VECTOR · SELF-CHECK ONLY";
    $("vector-status").dataset.tone = mismatch ? "stop" : "go";
    $("record").textContent = JSON.stringify({
      provenance: "project-authored explanatory browser preview",
      boundary: action ? "agent_action" : "interface_render",
      ...result,
      limits: action ? "no tool execution or authenticated approval" : "declared values, not objective measurements"
    }, null, 2);
    $("reproduce-link").href = action ?
      `action-lab.html?scenario=${recipient === "team" ? "send" : "changed"}` :
      `proof.html?attention=${attention}&restoration=${restoration}&lang=en`;
    $("reproduce-link").textContent = action ? "Open the interactive action lab ↗" : "Open this exact interface proof ↗";
    const next = buildNextStep(mode, attention, restoration, recipient);
    $("build-title").textContent = next.title;
    $("build-description").textContent = next.description;
    $("build-link").href = next.href;
    $("build-link").textContent = next.label;
    $("build-hint").textContent = next.hint;
    const source = document.querySelector(".links a:nth-child(2)");
    source.href = action ? "https://github.com/aruintelligence/aml-core/blob/main/pilots/action-boundary/README.md" :
      "https://github.com/aruintelligence/aml-core/blob/main/ETHICAL_RENDERING.md";
    const query = new URLSearchParams(action ? {mode, recipient} : {mode, attention: String(attention), restoration: String(restoration)});
    history.replaceState(null, "", `${location.pathname}?${query.toString()}#experience`);
  }

  document.querySelectorAll("[data-mode]").forEach(button => button.addEventListener("click", () => { mode = button.dataset.mode; update(); }));
  document.querySelectorAll("[data-recipient]").forEach(button => button.addEventListener("click", () => { recipient = button.dataset.recipient; update(); }));
  for (const id of ["attention", "restoration"]) $(id).addEventListener("input", update);
  $("copy-link").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(location.href);
      $("copy-link").textContent = "Scenario link copied";
    } catch {
      $("copy-link").textContent = "Copy unavailable — use the address bar";
    }
  });
  $("copy-record").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("record").textContent);
      $("copy-record").textContent = "Calculation copied";
    } catch {
      $("copy-record").textContent = "Copy unavailable — select the JSON below";
    }
  });
  update();
}
