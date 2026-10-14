// A viewer for a checked-in project report, not a verifier or live dispatch.
export const MATRIX_AXES = Object.freeze({
  policy: ["deny", "allow", "requires_approval", "ambiguous"],
  approval: ["match", "decline", "mismatch", "throw", "revoke", "mutate_caller"],
  claim: ["accept", "refuse", "throw_after_consume", "revoke_after_consume"],
  callback: ["return", "throw_after_write"]
});

const statuses = ["blocked", "dispatched", "unknown"];
export const matrixIndex = (policy, approval, claim, callback) =>
  (((MATRIX_AXES.policy.indexOf(policy) * 6 + MATRIX_AXES.approval.indexOf(approval)) * 4 +
    MATRIX_AXES.claim.indexOf(claim)) * 2 + MATRIX_AXES.callback.indexOf(callback));

export function inspectMatrix(report) {
  if (!report || report.protocol !== "aml-action-dispatch-matrix/1" ||
      report.provenance !== "project-authored bounded cross-product of local callbacks" ||
      !Array.isArray(report.rows) || report.rows.length !== 192 ||
      Object.keys(MATRIX_AXES).some(key => JSON.stringify(report.axes?.[key]) !== JSON.stringify(MATRIX_AXES[key]))) {
    throw new TypeError("Unexpected matrix format");
  }
  const counts = { blocked: 0, dispatched: 0, unknown: 0 };
  report.rows.forEach((row, index) => {
    const p = Math.floor(index / 48);
    const a = Math.floor(index / 8) % 6;
    const c = Math.floor(index / 2) % 4;
    const b = index % 2;
    if (!row || row.policy !== MATRIX_AXES.policy[p] || row.approval !== MATRIX_AXES.approval[a] ||
        row.claim !== MATRIX_AXES.claim[c] || row.callback !== MATRIX_AXES.callback[b] ||
        row.receipt?.protocol !== "aml-action-dispatch/1" ||
        !statuses.includes(row.receipt.execution_status) ||
        ![0, 1].includes(row.callback_count) || ![0, 1].includes(row.fixture_writes)) {
      throw new TypeError(`Malformed matrix vector ${index}`);
    }
    counts[row.receipt.execution_status]++;
  });
  // Detect a stale or partial report. The independent Python oracle is the real
  // row-by-row check in CI; these browser checks only guard this presentation.
  if (counts.blocked !== 140 || counts.dispatched !== 26 || counts.unknown !== 26) {
    throw new TypeError("Unexpected matrix totals");
  }
  return counts;
}

export function visibleMatrixIndices(report, policy = "all", status = "all") {
  if (!["all", ...MATRIX_AXES.policy].includes(policy) || !["all", ...statuses].includes(status)) {
    throw new RangeError("Unknown matrix filter");
  }
  return report.rows.flatMap((row, index) =>
    (policy === "all" || row.policy === policy) &&
    (status === "all" || row.receipt.execution_status === status) ? [index] : []);
}

export function matrixInsights(report) {
  return {
    spent_and_blocked: report.rows.filter(row => row.receipt.execution_status === "blocked" &&
      row.claims_consumed === 1 && row.callback_count === 0).length,
    unknown_after_write: report.rows.filter(row => row.receipt.execution_status === "unknown" &&
      row.callback_count === 1 && row.fixture_writes === 1).length,
    frozen_after_mutation: report.rows.filter(row => row.approval === "mutate_caller" &&
      row.callback_count === 1 && row.caller_target_after !== row.callback_target).length
  };
}

export function matrixUrl(currentUrl, index, report) {
  if (!Number.isInteger(index) || index < 0 || index >= report.rows.length) {
    throw new RangeError("Unknown matrix vector");
  }
  const url = new URL(currentUrl);
  url.searchParams.set("vector", String(index));
  url.hash = "case";
  return url.href;
}

export function matrixSelection(search, visible) {
  const value = new URLSearchParams(search).get("vector");
  const index = value !== null && /^(0|[1-9]\d*)$/.test(value) ? Number(value) : -1;
  return visible.includes(index) ? index : (visible[0] ?? null);
}

if (typeof document !== "undefined" && document.getElementById("matrix-grid")) {
  const $ = id => document.getElementById(id);
  const label = word => word.replaceAll("_", " ");
  const element = (tag, cls, text) => {
    const node = document.createElement(tag);
    node.className = cls;
    node.textContent = text;
    return node;
  };
  const params = new URLSearchParams(location.search);
  const startingPolicy = params.get("policy");
  const startingStatus = params.get("status");
  if (["all", ...MATRIX_AXES.policy].includes(startingPolicy)) $("policy-filter").value = startingPolicy;
  if (["all", ...statuses].includes(startingStatus)) $("status-filter").value = startingStatus;
  let report;
  let selected = params.has("vector") ? null : 49;
  let visible = [];

  function showCase(index, changeUrl = true) {
    selected = index;
    document.querySelectorAll(".vector").forEach(button =>
      button.setAttribute("aria-pressed", String(Number(button.dataset.index) === index)));
    const row = report.rows[index];
    const receipt = row.receipt;
    $("case-id").textContent = `VECTOR ${String(index + 1).padStart(3, "0")} / 192`;
    $("case-title").textContent = `${label(row.policy)} · ${label(row.approval)} · ${label(row.claim)} · ${label(row.callback)}`;
    $("case-receipt").textContent = receipt.execution_status.toUpperCase();
    $("case-receipt").dataset.status = receipt.execution_status;
    $("case-reason").textContent = `receipt.reason = ${receipt.reason}`;
    $("case-summary").textContent = receipt.execution_status === "unknown" ?
      "The callback was entered and wrote a local marker before it threw. The real outcome of a provider call would need reconciliation; do not silently retry." :
      receipt.execution_status === "dispatched" ?
        "The project fixture callback returned. This does not show external delivery." :
        row.claims_consumed ?
          "The local approval claim was consumed even though the tool callback was blocked. A blocked receipt does not mean the claim is reusable." :
          "The tool callback was not entered in this local vector.";
    const values = [
      ["01 / HOST POLICY", `${label(receipt.policy_decision)} · exact-match decision`],
      ["02 / APPROVAL HOOK", `${row.approval_requests} request · ${label(row.approval)} fixture`],
      ["03 / ONE-USE CLAIM", `${row.claim_attempts} attempt · ${row.claims_consumed} consumed`],
      ["04 / TOOL CALLBACK", `${row.callback_count} entry · ${row.fixture_writes} local marker write`]
    ];
    $("case-path").replaceChildren(...values.map(([name, value]) => {
      const item = element("li", "path-item", "");
      item.append(element("span", "path-label", name), element("strong", "", value));
      return item;
    }));
    $("case-caller").textContent = row.caller_target_after;
    $("case-target").textContent = row.callback_target ?? "No callback entry";
    $("case-digest").textContent = receipt.proposal_sha256 ?? "No digest (invalid or ambiguous policy)";
    $("case-json").textContent = JSON.stringify(row, null, 2);
    if (changeUrl) history.replaceState(null, "", matrixUrl(location.href, index, report));
  }

  function render() {
    const policy = $("policy-filter").value;
    const status = $("status-filter").value;
    visible = visibleMatrixIndices(report, policy, status);
    const visibleSet = new Set(visible);
    $("filter-count").textContent = `${visible.length} of 192 vectors shown`;
    const columns = MATRIX_AXES.policy.map(policyName => {
      const col = element("section", "policy-column", "");
      col.append(element("h3", "", label(policyName)));
      for (const approvalName of MATRIX_AXES.approval) {
        const group = element("div", "approval-group", "");
        group.append(element("h4", "", label(approvalName)));
        const cells = element("div", "cells", "");
        for (const claimName of MATRIX_AXES.claim) for (const callbackName of MATRIX_AXES.callback) {
          const index = matrixIndex(policyName, approvalName, claimName, callbackName);
          if (!visibleSet.has(index)) continue;
          const row = report.rows[index];
          const button = element("button", "vector", callbackName === "return" ? "↗" : "!");
          button.type = "button";
          button.dataset.index = String(index);
          button.dataset.status = row.receipt.execution_status;
          button.setAttribute("aria-label", `Vector ${index + 1}: ${[policyName, approvalName, claimName, callbackName].map(label).join(", ")}; ${row.receipt.execution_status}`);
          button.setAttribute("aria-pressed", "false");
          button.title = `${label(claimName)} / ${label(callbackName)} → ${row.receipt.execution_status}`;
          button.addEventListener("click", () => showCase(index));
          cells.append(button);
        }
        if (!cells.children.length) cells.append(element("span", "empty", "No matches"));
        group.append(cells);
        col.append(group);
      }
      return col;
    });
    $("matrix-grid").replaceChildren(...columns);
    if (visible.length) {
      const index = visibleSet.has(selected) ? selected : matrixSelection(location.search, visible);
      $("case").hidden = false;
      showCase(index, false);
    } else {
      selected = null;
      $("case").hidden = true;
    }
    const url = new URL(location.href);
    for (const [key, value] of [["policy", policy], ["status", status]]) {
      if (value === "all") url.searchParams.delete(key);
      else url.searchParams.set(key, value);
    }
    if (selected === null) url.searchParams.delete("vector");
    else url.searchParams.set("vector", String(selected));
    history.replaceState(null, "", url);
  }

  try {
    const response = await fetch("./action-dispatch-matrix.json");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    report = await response.json();
    const counts = inspectMatrix(report);
    for (const status of statuses) $(`count-${status}`).textContent = String(counts[status]);
    const insights = matrixInsights(report);
    for (const [name, count] of Object.entries(insights)) $(`insight-${name}`).textContent = `${count} vectors`;
    $("source-state").textContent = "Checked-in matrix loaded · 192 finite local vectors";
    $("policy-filter").addEventListener("change", render);
    $("status-filter").addEventListener("change", render);
    for (const button of document.querySelectorAll("[data-preset]")) {
      button.addEventListener("click", () => {
        $("policy-filter").value = "all";
        $("status-filter").value = "all";
        render();
        showCase(Number(button.dataset.preset));
        $("case").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
      });
    }
    $("copy-link").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(matrixUrl(location.href, selected, report));
        $("copy-status").textContent = "Case link copied.";
      } catch {
        $("copy-status").textContent = "Clipboard unavailable. Copy the address bar URL.";
      }
    });
    render();
  } catch (error) {
    $("source-state").textContent = `Report unavailable: ${error.message}`;
    $("source-state").dataset.error = "true";
    $("matrix-grid").replaceChildren(element("p", "", "The checked-in report could not be displayed. Use the raw JSON or run the local checks."));
    $("case").hidden = true;
  }
}
