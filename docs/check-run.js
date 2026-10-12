import { checkLocalRun, MAX_RECORD_CHARS } from "./check-run-core.js?v=local-check-1";

const $ = id => document.getElementById(id);
const input = $("record-input");
const status = $("input-status");

function clearResult() {
  $("results").hidden = true;
  $("empty").hidden = false;
  $("checks").replaceChildren();
  $("gates").replaceChildren();
}

function textNode(tag, value) {
  const node = document.createElement(tag);
  node.textContent = value;
  return node;
}

function render(result) {
  $("empty").hidden = true;
  $("results").hidden = false;
  $("result-head").dataset.state = result.consistent ? "pass" : "fail";
  $("result-title").textContent = result.consistent ? "Internally consistent" : "A check did not match";
  $("result-detail").textContent = result.consistent ?
    "The saved fields agree with this source and the current project compiler. This does not authenticate the run." :
    "Inspect the steps below. The saved file cannot be treated as a consistent account of this run.";
  const checks = $("checks");
  checks.replaceChildren();
  for (const item of result.checks) {
    const card = document.createElement("article");
    card.className = "check";
    card.dataset.state = item.pass ? "pass" : "fail";
    card.append(textNode("strong", `${item.pass ? "PASS" : "FAIL"} · ${item.label}`), textNode("p", item.detail));
    checks.append(card);
  }
  $("result-hash").textContent = `RECALCULATED SHA-256 · ${result.source_sha256}`;
  const gates = $("gates");
  gates.replaceChildren(textNode("h3", "Gate by gate"));
  for (const item of result.gates) {
    const row = document.createElement("article");
    row.className = "gate";
    row.dataset.state = item.pass ? "pass" : "fail";
    row.append(textNode("b", `${item.pass ? "MATCH" : "MISMATCH"} · ${item.identifier} · ${item.recorded}`), textNode("p", item.detail));
    gates.append(row);
  }
}

async function loadFile(file) {
  if (!file) return;
  clearResult();
  if (file.size > MAX_RECORD_CHARS) {
    status.textContent = "This file exceeds the 1 MB local check limit.";
    return;
  }
  try {
    input.value = await file.text();
    status.textContent = `${file.name} loaded locally. Recheck it below.`;
  } catch {
    status.textContent = "This browser could not read that file.";
  }
}

$("record-file").addEventListener("change", event => loadFile(event.target.files?.[0]));
const picker = $("file-picker");
picker.addEventListener("dragover", event => { event.preventDefault(); picker.dataset.drag = "on"; });
picker.addEventListener("dragleave", () => { picker.dataset.drag = "off"; });
picker.addEventListener("drop", event => {
  event.preventDefault();
  picker.dataset.drag = "off";
  loadFile(event.dataTransfer?.files?.[0]);
});
input.addEventListener("input", () => {
  clearResult();
  status.textContent = "Source record changed. Recheck to update the result.";
});
$("check").addEventListener("click", async () => {
  const raw = input.value;
  $("check").disabled = true;
  status.textContent = "Rechecking this local record…";
  try {
    const result = await checkLocalRun(raw);
    if (input.value !== raw) return;
    render(result);
    status.textContent = "Local recheck complete. The file was not uploaded.";
  } catch (error) {
    if (input.value !== raw) return;
    clearResult();
    status.textContent = error.message;
  } finally {
    $("check").disabled = false;
  }
});
