import { checkLocalRun, MAX_RECORD_CHARS } from "./check-run-core.js?v=local-check-1";

const $ = id => document.getElementById(id);
const input = $("record-input");
const status = $("input-status");
let originalExample = null;
let exampleMutation = null;

function exampleUrl(kind) {
  const url = new URL("./check-run.html", window.location.href);
  url.searchParams.set("example", "challenge");
  if (kind === "gate" || kind === "source") url.searchParams.set("probe", kind);
  return url;
}

function showExampleUrl(kind) {
  window.history.replaceState(null, "", exampleUrl(kind));
}

function leaveExample() {
  if (originalExample) {
    const url = new URL(window.location.href);
    url.searchParams.delete("example");
    url.searchParams.delete("probe");
    window.history.replaceState(null, "", url);
  }
  originalExample = null;
  exampleMutation = null;
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
  challenge.hidden = !originalExample || (!result.consistent && !exampleMutation);
  challenge.dataset.stage = exampleMutation ? "changed" : "captured";
  const content = exampleMutation === "gate" ? {
    stage: "02A / SAVED CLAIM CHANGED",
    title: "The claim changed. The source did not.",
    copy: "One saved browser outcome is inverted. Compare which checks catch it.",
    field: "gates[0].browser.effective_rendered",
    change: `${JSON.parse(originalExample).gates[0].browser.effective_rendered} → ${JSON.parse(input.value).gates[0].browser.effective_rendered}`,
    note: "Only this saved outcome changed; source bytes and declared inputs stayed intact."
  } : exampleMutation === "source" ? {
    stage: "02B / SOURCE BYTE ADDED",
    title: "The bytes changed. The rule did not.",
    copy: "One trailing line feed was added to the source. Compare the new fingerprint with the unchanged saved claim.",
    field: "source · trailing line feed (LF)",
    change: "original source → original source + 1 LF byte",
    note: "The saved SHA-256 was left as captured; the current compiler still sees the same decisions."
  } : {
    stage: "01 / CAPTURED RECORD", title: "Choose one change.",
    copy: "Flip a saved browser outcome or add one source byte. Each starts from the same captured record."
  };
  $("challenge-stage").textContent = content.stage;
  $("challenge-title").textContent = content.title;
  $("challenge-copy").textContent = content.copy;
  $("challenge-gate").setAttribute("aria-pressed", String(exampleMutation === "gate"));
  $("challenge-source").setAttribute("aria-pressed", String(exampleMutation === "source"));
  $("challenge-copy-link").textContent = "Copy this example link ↗";
  $("challenge-restore").hidden = !exampleMutation;
  $("challenge-delta").hidden = !exampleMutation;
  if (exampleMutation) {
    $("challenge-field").textContent = content.field;
    $("challenge-change").textContent = content.change;
    $("challenge-note").textContent = content.note;
  }
  for (const item of result.checks) {
    const signal = $(`signal-${item.id}`);
    signal.dataset.state = item.pass ? "pass" : "fail";
    signal.textContent = `${item.pass ? "PASS" : "FAIL"} / ${item.id === "hash" ? "SOURCE SHA" : item.id === "compiler" ? "COMPILER" : "GATE CLAIMS"}`;
  }
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
  for (const id of ["challenge-gate", "challenge-source", "challenge-restore"]) $(id).disabled = true;
  status.textContent = "Rechecking this local record…";
  try {
    const result = await checkLocalRun(raw);
    if (input.value !== raw) return;
    render(result);
    status.textContent = originalExample ?
      exampleMutation === "gate" ? "One saved browser outcome changed; the source bytes stayed intact." :
        exampleMutation === "source" ? "One LF byte added to the source; the saved fingerprint was left intact." :
          "Captured project example rechecked in this browser. No record was uploaded." :
      "Local recheck complete. The file was not uploaded.";
  } catch (error) {
    if (input.value !== raw) return;
    clearResult();
    status.textContent = error.message;
  } finally {
    $("check").disabled = false;
    for (const id of ["challenge-gate", "challenge-source", "challenge-restore"]) $(id).disabled = false;
  }
}

$("check").addEventListener("click", recheck);
async function loadExample(focusChallenge = false, initialProbe = null) {
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
    if (initialProbe) await changeExample(initialProbe, false);
    else {
      await recheck();
      showExampleUrl(null);
    }
    if (focusChallenge && !$("sample-challenge").hidden) {
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
$("load-example").addEventListener("click", () => loadExample(true));
$("load-example-hero").addEventListener("click", () => loadExample(true));
const incoming = new URLSearchParams(window.location.search);
if (incoming.get("example") === "challenge") {
  const probe = incoming.get("probe");
  loadExample(true, probe === "gate" || probe === "source" ? probe : null);
}

async function changeExample(kind, focusChallenge = true) {
  if (!originalExample) return;
  exampleMutation = kind;
  const record = JSON.parse(originalExample);
  if (kind === "gate") record.gates[0].browser.effective_rendered = !record.gates[0].browser.effective_rendered;
  if (kind === "source") record.source += "\n";
  input.value = JSON.stringify(record, null, 2);
  await recheck();
  showExampleUrl(kind);
  if (focusChallenge) $("sample-challenge").scrollIntoView({ block: "center" });
}
$("challenge-gate").addEventListener("click", () => changeExample("gate"));
$("challenge-source").addEventListener("click", () => changeExample("source"));
$("challenge-restore").addEventListener("click", () => changeExample(null));
$("challenge-copy-link").addEventListener("click", async () => {
  if (!originalExample) return;
  const button = $("challenge-copy-link");
  try {
    await navigator.clipboard.writeText(exampleUrl(exampleMutation).href);
    button.textContent = "Example link copied ✓";
  } catch {
    button.textContent = "Copy unavailable · use page address";
  }
});
