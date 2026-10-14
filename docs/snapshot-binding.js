// Presents checked-in project fixtures. The Python oracle verifies the current report in CI.
export const SNAPSHOT_MODES = Object.freeze(["allow", "requires_approval"]);

export function inspectSnapshotEvidence(report, mutants) {
  const mutation = mutants?.mutations?.find(item => item.id === "double_snapshot_receipt_split");
  if (report?.protocol !== "aml-action-snapshot-proof/1" ||
      report.provenance !== "project-authored stateful accessor and local callback fixtures" ||
      mutants?.protocol !== "aml-action-dispatch-mutants/1" ||
      mutants.boundary_source_sha256 !== report.boundary_source_sha256 ||
      mutants.snapshot_cases !== 2 || mutants.summary?.combined_detected !== 10 ||
      !Array.isArray(report.rows) || report.rows.length !== 2 ||
      mutation?.snapshot_changed_cases !== 2 || !Array.isArray(mutation.snapshot_changes) ||
      mutation.snapshot_changes.length !== 2) {
    throw new TypeError("Unexpected snapshot evidence format");
  }
  report.rows.forEach((current, index) => {
    const change = mutation.snapshot_changes[index];
    const previous = change?.mutant;
    if (current.mode !== SNAPSHOT_MODES[index] || change.index !== index ||
        change.mode !== current.mode || JSON.stringify(change.reference) !== JSON.stringify(current) ||
        current.accessor_reads !== 1 || current.callback_body !== "First observed body" ||
        current.callback_count !== 1 || current.receipt_matches_callback !== true ||
        current.receipt?.proposal_sha256 !== current.callback_sha256 ||
        previous?.accessor_reads !== 2 || previous.callback_body !== "Changed on second read" ||
        previous.callback_count !== 1 || previous.receipt_matches_callback !== false ||
        previous.receipt?.proposal_sha256 === previous.callback_sha256 ||
        current.receipt?.execution_status !== "dispatched" ||
        previous.receipt?.execution_status !== "dispatched") {
      throw new TypeError(`Malformed snapshot comparison ${index}`);
    }
  });
  return mutation.snapshot_changes;
}

export function snapshotSelection(search) {
  const value = new URLSearchParams(search).get("mode");
  return SNAPSHOT_MODES.includes(value) ? value : "allow";
}

export function snapshotUrl(currentUrl, mode) {
  if (!SNAPSHOT_MODES.includes(mode)) throw new RangeError("Unknown snapshot mode");
  const url = new URL(currentUrl);
  url.searchParams.set("mode", mode);
  url.hash = "comparison";
  return url.href;
}

if (typeof document !== "undefined" && document.getElementById("comparison")) {
  const $ = id => document.getElementById(id);
  const state = $("report-state");
  try {
    const responses = await Promise.all([
      fetch("./action-snapshot-proof.json"), fetch("./action-dispatch-mutants.json")
    ]);
    if (responses.some(response => !response.ok)) throw new Error("HTTP report error");
    const [report, mutants] = await Promise.all(responses.map(response => response.json()));
    const changes = inspectSnapshotEvidence(report, mutants);
    let selected = snapshotSelection(location.search);
    const short = hash => `${hash.slice(0, 12)}…${hash.slice(-8)}`;
    function render(mode, updateUrl = true) {
      selected = mode;
      const index = SNAPSHOT_MODES.indexOf(mode);
      const now = report.rows[index];
      const before = changes[index].mutant;
      $("mode-title").textContent = mode === "allow" ? "Allow rule" : "Approval-required rule";
      $("mode-note").textContent = mode === "allow" ?
        "A host allow rule permits this local callback. Both receipts say dispatched, but only the corrected one identifies what reached it." :
        "A fixture approval echoes the offered digest and its one-use claim succeeds. The second read still splits the receipt from the callback in the regression.";
      document.querySelectorAll("[data-mode]").forEach(button =>
        button.setAttribute("aria-pressed", String(button.dataset.mode === mode)));
      for (const [prefix, row] of [["before", before], ["after", now]]) {
        $(`${prefix}-reads`).textContent = `${row.accessor_reads} ${row.accessor_reads === 1 ? "read" : "reads"}`;
        $(`${prefix}-body`).textContent = row.callback_body;
        $(`${prefix}-receipt`).textContent = short(row.receipt.proposal_sha256);
        $(`${prefix}-callback`).textContent = short(row.callback_sha256);
        $(`${prefix}-verdict`).textContent = row.receipt_matches_callback ? "BOUND TO CALLBACK" : "RECEIPT SPLIT";
        $(`${prefix}-verdict`).dataset.bound = String(row.receipt_matches_callback);
        $(`${prefix}-approval`).textContent = row.approval_requests ?
          `${row.approval_requests} fixture request · ${row.claim_attempts} claim` : "No approval hook";
        $(`${prefix}-raw`).textContent = JSON.stringify(row, null, 2);
      }
      if (updateUrl) history.replaceState(null, "", snapshotUrl(location.href, mode));
    }
    document.querySelectorAll("[data-mode]").forEach(button =>
      button.addEventListener("click", () => render(button.dataset.mode)));
    $("copy-link").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(snapshotUrl(location.href, selected));
        $("copy-status").textContent = "Comparison link copied.";
      } catch { $("copy-status").textContent = "Clipboard unavailable. Copy the address bar URL."; }
    });
    state.textContent = "Current report and source mutation loaded";
    render(selected, false);
  } catch (error) {
    state.textContent = `Evidence unavailable: ${error.message}`;
    state.dataset.error = "true";
    $("comparison").hidden = true;
  }
}
