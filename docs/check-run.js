import { checkLocalRun, MAX_RECORD_CHARS } from "./check-run-core.js?v=local-check-1";

const $ = id => document.getElementById(id);
const input = $("record-input");
const status = $("input-status");
let originalExample = null;
let exampleChanged = false;

function leaveExample() {
  originalExample = null;
  exampleChanged = false;
  $("sample-challenge").hidden = true;
}

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
  const challenge = $("sample-challenge");
  challenge.hidden = !originalExample || (!result.consistent && !exampleChanged);
  challenge.dataset.stage = exampleChanged ? "changed" : "captured";
  $("challenge-stage").textContent = exampleChanged ? "02 / CHANGED SAVED CLAIM" : "01 / CAPTURED RECORD";
  $("challenge-title").textContent = exampleChanged ? "The source stayed. The claim broke." : "Now challenge the claim.";
  $("challenge-button").textContent = exampleChanged ? "Restore the captured example ↺" : "Change one saved claim ↗";
  $("challenge-copy").textContent = exampleChanged ?
    "SHA-256 and compiler replay still pass. One saved gate outcome now disagrees. Restore the captured claim to check it again." :
    "Flip the withheld gate’s saved browser outcome. The source fingerprint will still match while the gate claim fails.";
}

async function loadFile(file) {
  if (!file) return;
  leaveExample();
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
  leaveExample();
  clearResult();
  status.textContent = "Source record changed. Recheck to update the result.";
});
async function recheck() {
  const raw = input.value;
  $("check").disabled = true;
  $("challenge-button").disabled = true;
  status.textContent = "Rechecking this local record…";
  try {
    const result = await checkLocalRun(raw);
    if (input.value !== raw) return;
    render(result);
    status.textContent = originalExample ?
      exampleChanged ? "The example's saved outcome changed. The source fingerprint still matches." :
        "Captured project example rechecked in this browser. No record was uploaded." :
      "Local recheck complete. The file was not uploaded.";
  } catch (error) {
    if (input.value !== raw) return;
    clearResult();
    status.textContent = error.message;
  } finally {
    $("check").disabled = false;
    $("challenge-button").disabled = false;
  }
}

$("check").addEventListener("click", recheck);
async function loadExample(focusChallenge = false) {
  const before = input.value;
  $("load-example").disabled = true;
  $("load-example-hero").disabled = true;
  status.textContent = "Loading the captured project example…";
  try {
    const response = await fetch("./example-local-run.json");
    if (!response.ok) throw new Error("The example record could not be loaded here.");
    const raw = await response.text();
    if (input.value !== before) return;
    if (raw.length > MAX_RECORD_CHARS) throw new RangeError("The example exceeds the local check limit.");
    const formatted = JSON.stringify(JSON.parse(raw), null, 2);
    leaveExample();
    $("record-file").value = "";
    input.value = formatted;
    originalExample = formatted;
    clearResult();
    await recheck();
    if (focusChallenge) {
      $("sample-challenge").scrollIntoView({ block: "center" });
      $("sample-challenge").focus({ preventScroll: true });
    }
  } catch {
    if (input.value === before) status.textContent = "The example record could not be loaded here. Create a run in the playground instead.";
  } finally {
    $("load-example").disabled = false;
    $("load-example-hero").disabled = false;
  }
}
$("load-example").addEventListener("click", () => loadExample());
$("load-example-hero").addEventListener("click", () => loadExample(true));
if (new URLSearchParams(window.location.search).get("example") === "challenge") loadExample(true);

$("challenge-button").addEventListener("click", async () => {
  if (!originalExample) return;
  exampleChanged = !exampleChanged;
  const record = JSON.parse(originalExample);
  if (exampleChanged) record.gates[0].browser.effective_rendered = !record.gates[0].browser.effective_rendered;
  input.value = JSON.stringify(record, null, 2);
  await recheck();
  $("sample-challenge").scrollIntoView({ block: "center" });
});
