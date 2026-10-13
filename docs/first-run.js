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

export function firstRunScenarioUrl(currentUrl, mode, attention, restoration, recipient = "outside", jump = false) {
  const url = new URL(currentUrl);
  if (mode === "action") {
    if (recipient !== "team" && recipient !== "outside") throw new RangeError("Unknown first-run recipient");
    url.search = new URLSearchParams({ mode, recipient }).toString();
  } else if (mode === "render") {
    renderDecision(attention, restoration);
    url.search = new URLSearchParams({ mode, attention: String(attention), restoration: String(restoration) }).toString();
  } else {
    throw new RangeError("Unknown first-run mode");
  }
  // Keep the visitor's position. A copied deep link deliberately jumps to the experiment.
  if (jump) url.hash = "experience";
  return url.href;
}

// This describes the observed local path after the policy calculation. A
// matching action is still only a plan; this page never grants approval.
export function firstRunContinuation(mode, result, attention = 5, restoration = 1, recipient = "outside") {
  if (mode === "action") {
    if (recipient !== "team" && recipient !== "outside") throw new RangeError("Unknown first-run recipient");
    const shared = [
      { name: "Host approval", value: "Not issued here", tone: "idle" },
      { name: "Tool callback", value: "0 invocations", tone: "idle" }
    ];
    if (!result.project_vector_matches) return {
      title: "Pause on the mismatch.",
      steps: [{ name: "Project vector", value: "Disagreement to investigate", tone: "stop" }, ...shared],
      probe: null
    };
    const matched = result.decision === "requires_approval";
    return {
      title: matched ? "The host still has to approve." : "This action stops at policy.",
      steps: [
        { name: "Exact host rule", value: matched ? "Matched this destination" : "No matching destination", tone: matched ? "go" : "stop" },
        { name: "Host approval", value: matched ? "Required; not issued" : "Not reached", tone: matched ? "hold" : "idle" },
        shared[1]
      ],
      probe: { label: matched ? "Try the outside route →" : "Try the policy route →",
        recipient: matched ? "outside" : "team" }
    };
  }
  if (mode !== "render") throw new RangeError("Unknown first-run mode");
  renderDecision(attention, restoration);
  const decided = result.decision === "allow" || result.decision === "suppress";
  if (!decided || !result.gate_event) return {
    title: "The browser gate has no usable result.",
    steps: [
      { name: "Gate event", value: "No usable decision", tone: "hold" },
      { name: "Element", value: "Withheld while unavailable", tone: "hold" },
      { name: "Evidence", value: "No successful event", tone: "idle" }
    ], probe: null
  };
  const allowed = result.decision === "allow";
  return {
    title: allowed ? "The element reaches this screen." : "The element stays off this screen.",
    steps: [
      { name: "Gate event", value: `${result.decision} · enforce / closed`, tone: allowed ? "go" : "stop" },
      { name: "Element", value: allowed ? "Visible in this page" : "Hidden in this page", tone: allowed ? "go" : "stop" },
      { name: "Evidence", value: "Local browser event only", tone: "idle" }
    ],
    probe: allowed ? { label: "Make the gate withhold it →",
      attention: attention === 0 ? 1 : attention, restoration: attention === 0 ? 0 : attention - 1 } :
      { label: "Meet the threshold →", attention, restoration: attention }
  };
}

if (typeof document !== "undefined" && document.getElementById("experience")) {
  const $ = id => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  let mode = params.get("mode") === "render" ? "render" : "action";
  let recipient = params.get("recipient") === "team" ? "team" : "outside";
  let bridgeState = "loading";
  let probe = null;
  const initial = (name, fallback) => {
    const raw = params.get(name);
    if (raw === null || !/^(10|[0-9])$/.test(raw)) return fallback;
    return Number(raw);
  };
  $("attention").value = initial("attention", 5);
  $("restoration").value = initial("restoration", 1);

  function browserGateResult(attention, restoration) {
    renderDecision(attention, restoration); // Validate the slider range before creating the element.
    const proposed = "render a conversion prompt";
    const policy = "restoration_value >= attention_cost";
    if (bridgeState !== "ready") {
      $("gate-slot").replaceChildren();
      $("gate-placeholder").hidden = false;
      $("gate-placeholder").textContent = bridgeState === "loading" ?
        "Connecting to the project browser gate…" : "The browser gate could not load here.";
      $("gate-event").textContent = "No successful aml-decision";
      return { proposed, policy, attention_cost: attention, restoration_value: restoration,
        decision: bridgeState, reason: "browser_gate_not_available" };
    }

    // The listener is present before connection: the custom element evaluates as
    // it enters the document and may hide itself in enforce/closed mode.
    const gate = document.createElement("aml-gate");
    gate.setAttribute("purpose", "Review an offer without urgency");
    gate.setAttribute("attention-cost", String(attention));
    gate.setAttribute("restoration-value", String(restoration));
    gate.setAttribute("mode", "enforce");
    gate.setAttribute("failure-mode", "closed");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Review the offer";
    gate.append(button);
    let detail = null;
    gate.addEventListener("aml-decision", event => { detail = event.detail; });
    $("gate-slot").replaceChildren(gate);
    const ok = detail?.ok === true && detail.deployment_mode === "enforce" &&
      detail.failure_mode === "closed" && typeof detail.render_allowed === "boolean" &&
      typeof detail.effective_rendered === "boolean" &&
      detail.effective_rendered === detail.render_allowed &&
      detail.attention_cost === attention && detail.restoration_value === restoration &&
      gate.hidden === !detail.effective_rendered;
    if (!ok) gate.hidden = true;
    $("gate-placeholder").hidden = ok && detail.effective_rendered;
    $("gate-placeholder").textContent = ok ? "Element withheld by the browser gate" :
      "The browser gate did not return a usable enforce/closed decision.";
    $("gate-event").textContent = ok ?
      `aml-decision · ${detail.render_allowed ? "allow" : "suppress"} · ${detail.effective_rendered ? "visible" : "hidden"}` :
      "No usable aml-decision";
    return { proposed, policy, attention_cost: attention, restoration_value: restoration,
      decision: ok ? (detail.render_allowed ? "allow" : "suppress") : "unavailable",
      reason: ok ? (detail.render_allowed ? "declared_value_meets_cost" : "declared_value_below_cost") :
        "browser_gate_decision_unavailable",
      gate_event: ok ? { render_allowed: detail.render_allowed, effective_rendered: detail.effective_rendered,
        deployment_mode: detail.deployment_mode, failure_mode: detail.failure_mode,
        attention_cost: detail.attention_cost, restoration_value: detail.restoration_value } : null };
  }

  let generation = 0;
  async function update() {
    const turn = ++generation;
    const action = mode === "action";
    const attention = Number($("attention").value);
    const restoration = Number($("restoration").value);
    $("screen-preview").hidden = action;
    if (action) $("gate-slot").replaceChildren();
    let result;
    try {
      result = action ? await firstRunAction(recipient, globalThis.crypto?.subtle) :
        browserGateResult(attention, restoration);
    } catch {
      result = action ? { proposed: `send_message → ${recipient === "team" ? "team" : "outsider"}@example.test`,
        decision: "deny", reason: "browser_crypto_unavailable", proposal_sha256: null,
        project_vector_matches: false, tool_callbacks: 0 } :
        { proposed: "render a conversion prompt", decision: "unavailable", reason: "browser_gate_error" };
    }
    if (turn !== generation) return; // An older asynchronous digest must not overwrite a new input.
    const mismatch = action && !result.project_vector_matches;
    const tone = action ? (result.decision === "deny" || mismatch ? "stop" : "hold") :
      (result.decision === "allow" ? "go" : result.decision === "suppress" ? "stop" : "hold");

    document.querySelectorAll("[data-mode]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.mode === mode)));
    document.querySelectorAll("[data-recipient]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.recipient === recipient)));
    $("action-controls").hidden = !action;
    $("render-controls").hidden = action;
    $("experience-title").textContent = action ? "Move the destination." : "Change what reaches the screen.";
    $("instruction").textContent = action ?
      "An agent proposes send_message. The host has one exact rule for the team destination and still requires approval for a matching action." :
      "An app proposes a conversion prompt. The project browser gate evaluates its declared values before the element reaches the screen.";
    $("attention-value").textContent = String(attention);
    $("restoration-value").textContent = String(restoration);
    if (action) {
      const tool = document.createElement("span");
      tool.textContent = "send_message →";
      const destination = document.createElement("span");
      destination.className = "route-destination";
      destination.textContent = recipient === "team" ? "team@example.test" : "outsider@example.test";
      $("path-proposal").replaceChildren(tool, destination);
    } else {
      $("path-proposal").textContent = result.proposed;
    }
    $("path-rule").textContent = action ? "team@example.test only" : "restoration ≥ attention";
    $("path-result").textContent = mismatch ? "VECTOR MISMATCH" : result.decision.replaceAll("_", " ").toUpperCase();
    $("path-result-card").dataset.tone = tone;
    $("orb").dataset.tone = tone;
    $("orb-word").textContent = action ? (mismatch ? "RECHECK" : tone === "stop" ? "BLOCKED" : "HELD") :
      (tone === "go" ? "VISIBLE" : tone === "stop" ? "WITHHELD" : "CHECKING");
    $("verdict-label").textContent = action ? "ACTION HELD BEFORE DISPATCH" : "BROWSER GATE DECISION";
    $("verdict-title").textContent = action ? (mismatch ? "The published vector did not match." : tone === "stop" ? "The route does not match." : "The route matches. Approval is next.") :
      (tone === "go" ? "The gate made this element visible." : tone === "stop" ? "The gate withheld this element." :
        result.decision === "loading" ? "Connecting to the browser gate." : "The browser gate is unavailable.");
    $("verdict-explanation").textContent = mismatch ?
      "Do not rely on this preview. Open the source vectors and executable lab to investigate the disagreement." : action ? (tone === "stop" ?
      "The exact host rule cannot authorize this destination. The local preview invokes no tool." :
      "An exact rule match still does not dispatch the tool. A real host must approve the exact proposal first.") :
      (tone === "go" ? "The emitted decision allows this element under the declared prototype values." :
      tone === "stop" ? "The emitted decision suppresses this element under the declared prototype values." :
      "No successful gate decision is available. Open the project proof to inspect the source.");
    $("screen-preview").dataset.tone = tone;
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
      limits: action ? "no tool execution or authenticated approval" :
        "browser gate event from declared values; not objective measurements"
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
    const continuation = firstRunContinuation(mode, result, attention, restoration, recipient);
    $("continuation-title").textContent = continuation.title;
    $("continuation-steps").replaceChildren(...continuation.steps.map(step => {
      const item = document.createElement("li");
      item.dataset.tone = step.tone;
      const name = document.createElement("span");
      name.textContent = step.name;
      const value = document.createElement("strong");
      value.textContent = step.value;
      item.append(name, value);
      return item;
    }));
    probe = continuation.probe;
    $("next-probe").hidden = !probe;
    if (probe) $("next-probe").textContent = probe.label;
    $("continue-link").href = mismatch ? $("reproduce-link").href : next.href;
    $("continue-link").textContent = mismatch ? "Investigate the vector ↗" : next.label;
    const source = document.querySelector(".links a:nth-child(2)");
    source.href = action ? "https://github.com/aruintelligence/aml-core/blob/main/pilots/action-boundary/README.md" :
      "https://github.com/aruintelligence/aml-core/blob/main/ETHICAL_RENDERING.md";
    history.replaceState(null, "", firstRunScenarioUrl(location.href, mode, attention, restoration, recipient));
  }

  document.querySelectorAll("[data-mode]").forEach(button => button.addEventListener("click", () => { mode = button.dataset.mode; update(); }));
  document.querySelectorAll("[data-recipient]").forEach(button => button.addEventListener("click", () => { recipient = button.dataset.recipient; update(); }));
  for (const id of ["attention", "restoration"]) $(id).addEventListener("input", update);
  $("next-probe").addEventListener("click", () => {
    if (!probe) return;
    if (mode === "action") recipient = probe.recipient;
    else {
      $("attention").value = probe.attention;
      $("restoration").value = probe.restoration;
    }
    update();
  });
  $("copy-link").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(firstRunScenarioUrl(location.href, mode,
        Number($("attention").value), Number($("restoration").value), recipient, true));
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
  import("./aml-gate.js").then(() => {
    bridgeState = "ready";
    if (mode === "render") update();
  }).catch(() => {
    bridgeState = "unavailable";
    if (mode === "render") update();
  });
}
