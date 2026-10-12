// Explanatory preview only. Source implementations and receipt verification live in the repo.
export function actionDecision(recipient) {
  const matched = recipient === "team";
  return {
    proposed: `send_message → ${matched ? "team" : "outsider"}@example.test`,
    policy: "send_message → team@example.test; approval required",
    decision: matched ? "requires_approval" : "deny",
    reason: matched ? "exact_rule" : "no_exact_rule",
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

if (typeof document !== "undefined") {
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

  function update() {
    const action = mode === "action";
    const attention = Number($("attention").value);
    const restoration = Number($("restoration").value);
    const result = action ? actionDecision(recipient) : renderDecision(attention, restoration);
    const tone = action ? (result.decision === "deny" ? "stop" : "hold") :
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
    $("path-result").textContent = result.decision.replaceAll("_", " ").toUpperCase();
    $("path-result-card").dataset.tone = tone;
    $("orb").dataset.tone = tone;
    $("orb-word").textContent = action ? (tone === "stop" ? "BLOCKED" : "HELD") :
      (tone === "go" ? "VISIBLE" : "WITHHELD");
    $("verdict-label").textContent = action ? "ACTION HELD BEFORE DISPATCH" : "INTERFACE RENDER DECISION";
    $("verdict-title").textContent = action ? (tone === "stop" ? "The route does not match." : "The route matches. Approval is next.") :
      (tone === "go" ? "This element passes the gate." : "This element is suppressed.");
    $("verdict-explanation").textContent = action ? (tone === "stop" ?
      "The exact host rule cannot authorize this destination. The local preview invokes no tool." :
      "An exact rule match still does not dispatch the tool. A real host must approve the exact proposal first.") :
      (tone === "go" ? "Declared restoration meets or exceeds declared attention cost under this prototype rule." :
      "Declared restoration is below declared attention cost under this prototype rule.");
    $("screen-preview").dataset.tone = tone;
    $("screen-title").textContent = tone === "go" ? "Continue with the offer" : "Suppressed by policy";
    $("screen-detail").textContent = tone === "go" ? "A local illustration of an allowed prompt." :
      "The proposed prompt is withheld in this local illustration.";
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
  update();
}
