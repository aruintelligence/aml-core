// This viewer presents checked-in local observations; the Python oracle is the verifier.
export const TUPLE_AXES = Object.freeze({
  tool: ["exact", "other"], effect: ["exact", "other"], resource: ["exact", "other"]
});

export const tupleIndex = (tool, effect, resource) =>
  TUPLE_AXES.tool.indexOf(tool) * 4 + TUPLE_AXES.effect.indexOf(effect) * 2 +
  TUPLE_AXES.resource.indexOf(resource);

export function inspectPolicyTuple(report) {
  if (report?.protocol !== "aml-action-policy-tuple/1" ||
      report.provenance !== "project-authored local eight-case rule-binding cross-product" ||
      !Array.isArray(report.rows) || report.rows.length !== 8 ||
      Object.keys(TUPLE_AXES).some(key => JSON.stringify(report.axes?.[key]) !== JSON.stringify(TUPLE_AXES[key]))) {
    throw new TypeError("Unexpected policy tuple format");
  }
  report.rows.forEach((row, index) => {
    const expectedMatch = { tool: TUPLE_AXES.tool[Math.floor(index / 4)],
      effect: TUPLE_AXES.effect[Math.floor(index / 2) % 2],
      resource: TUPLE_AXES.resource[index % 2] };
    const exact = index === 0;
    if (JSON.stringify(row.match) !== JSON.stringify(expectedMatch) ||
        !["tool", "effect", "resource"].every(key =>
          typeof row.proposal?.[key] === "string" && typeof row.rule?.[key] === "string" &&
          (row.proposal[key] === row.rule[key]) === (expectedMatch[key] === "exact")) ||
        row.receipt?.protocol !== "aml-action-dispatch/1" ||
        !/^[a-f0-9]{64}$/.test(row.receipt.proposal_sha256 ?? "") ||
        row.receipt.policy_decision !== (exact ? "allow" : "deny") ||
        row.receipt.execution_status !== (exact ? "dispatched" : "blocked") ||
        row.receipt.reason !== (exact ? "host_dispatch_returned" : "no_exact_rule") ||
        row.callback_count !== Number(exact) ||
        row.callback_target !== (exact ? "team@example.test" : null)) {
      throw new TypeError(`Malformed policy tuple case ${index}`);
    }
  });
  return { dispatched: 1, blocked: 7 };
}

export function tupleSelection(search) {
  const value = new URLSearchParams(search).get("case");
  return value !== null && /^(0|[1-7])$/.test(value) ? Number(value) : 0;
}

export function tupleUrl(currentUrl, index) {
  if (!Number.isInteger(index) || index < 0 || index > 7) throw new RangeError("Unknown tuple case");
  const url = new URL(currentUrl);
  url.searchParams.set("case", String(index));
  url.hash = "inspection";
  return url.href;
}

if (typeof document !== "undefined" && document.getElementById("tuple-grid")) {
  const $ = id => document.getElementById(id);
  const element = (tag, cls, value = "") => {
    const node = document.createElement(tag);
    node.className = cls;
    node.textContent = value;
    return node;
  };
  const names = { tool: "TOOL", effect: "EFFECT", resource: "RESOURCE" };
  const reportState = $("report-state");
  try {
    const response = await fetch("./action-policy-tuple.json");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const report = await response.json();
    inspectPolicyTuple(report);
    let selected = tupleSelection(location.search);
    function showCase(index, changeUrl = true) {
      selected = index;
      const row = report.rows[index];
      const exact = index === 0;
      document.querySelectorAll(".tuple-cell").forEach(button =>
        button.setAttribute("aria-pressed", String(Number(button.dataset.index) === index)));
      $("case-number").textContent = `CASE ${String(index + 1).padStart(2, "0")} / 08`;
      $("case-heading").textContent = exact ? "All three fields agree." :
        `${Object.entries(row.match).filter(([, value]) => value === "other").map(([key]) => key).join(" + ")} differs.`;
      $("case-note").textContent = exact ?
        "The one valid allow rule binds tool, effect, and resource. The local callback returned once." :
        "The host finds no exact rule. Approval and the local callback are never entered.";
      $("case-status").textContent = row.receipt.execution_status.toUpperCase();
      $("case-status").dataset.status = row.receipt.execution_status;
      $("case-reason").textContent = row.receipt.reason;
      $("case-callback").textContent = `${row.callback_count} ${row.callback_count === 1 ? "entry" : "entries"}`;
      $("case-target").textContent = row.callback_target ?? "No callback entry";
      $("case-digest").textContent = row.receipt.proposal_sha256;
      $("binding-rows").replaceChildren(...Object.keys(names).map(key => {
        const binding = element("tr", row.match[key] === "exact" ? "binding-exact" : "binding-other");
        const header = element("th", "", names[key]);
        header.scope = "row";
        binding.append(header, element("td", "", row.proposal[key]), element("td", "", row.rule[key]),
          element("td", "", row.match[key] === "exact" ? "MATCH" : "DIFFERENT"));
        return binding;
      }));
      $("raw-case").textContent = JSON.stringify(row, null, 2);
      if (changeUrl) history.replaceState(null, "", tupleUrl(location.href, index));
    }
    const panels = TUPLE_AXES.resource.map(resource => {
      const panel = element("section", "tuple-panel");
      panel.dataset.scope = resource;
      panel.append(element("span", "panel-eyebrow", resource === "exact" ? "LAYER 01 · RESOURCE MATCHES" : "LAYER 02 · RESOURCE DIFFERS"),
        element("h3", "", resource === "exact" ? "Same destination" : "Other destination"));
      const grid = element("div", "panel-grid");
      for (const tool of TUPLE_AXES.tool) for (const effect of TUPLE_AXES.effect) {
        const index = tupleIndex(tool, effect, resource);
        const row = report.rows[index];
        const button = element("button", "tuple-cell");
        button.type = "button";
        button.dataset.index = String(index);
        button.dataset.status = row.receipt.execution_status;
        button.setAttribute("aria-label", `Case ${index + 1}: tool ${tool}, effect ${effect}, resource ${resource}; ${row.receipt.execution_status}`);
        button.setAttribute("aria-pressed", "false");
        button.append(element("span", "cell-index", `0${index + 1} / 08`),
          element("strong", "", `Tool ${tool} · Effect ${effect}`),
          element("span", "cell-status", row.receipt.execution_status === "dispatched" ? "CALLBACK RETURNED ↗" : "NO CALLBACK ↗"));
        button.addEventListener("click", () => showCase(index));
        grid.append(button);
      }
      panel.append(grid);
      return panel;
    });
    $("tuple-grid").replaceChildren(...panels);
    $("copy-link").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(tupleUrl(location.href, selected));
        $("copy-status").textContent = "Case link copied.";
      } catch { $("copy-status").textContent = "Clipboard unavailable. Copy the address bar URL."; }
    });
    reportState.textContent = "Checked-in eight-case report loaded";
    showCase(selected, false);
  } catch (error) {
    reportState.textContent = `Report unavailable: ${error.message}`;
    reportState.dataset.error = "true";
    $("tuple-grid").replaceChildren(element("p", "", "The checked-in report could not be displayed. Run the local checks or inspect the raw JSON."));
    $("inspection").hidden = true;
  }
}
