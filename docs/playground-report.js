import { buildComparisonCard } from "./playground-card.js";
import { playgroundShareUrl } from "./playground-core.js";

function html(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function gateRow(gate, number) {
  const { attention_cost: cost, restoration_value: value } = gate.declaration;
  const allowed = gate.browser.effective_rendered;
  return `<article class="gate ${allowed ? "allow" : "suppress"}">
    <div class="gate-top"><span>${number} / ENGRAM</span><strong>${allowed ? "VISIBLE" : "WITHHELD"}</strong></div>
    <h3>${html(gate.identifier)}</h3>
    <p class="element">${html(gate.declaration.label)}</p>
    <p class="purpose">${html(gate.declaration.purpose)}</p>
    <div class="rule"><span>DECLARED RULE</span><b>${html(value)} ${value >= cost ? "≥" : "&lt;"} ${html(cost)}</b><span>restoration ${value >= cost ? "meets" : "falls below"} attention cost</span></div>
    <p class="result">Compiler: <b>${allowed ? "allow" : "suppress"}</b> · Browser: <b>${allowed ? "visible" : "withheld"}</b> · Event matched</p>
  </article>`;
}

// A standalone, script-free report. It is generated only from a matched local run.
export function buildComparisonReport(record) {
  const card = buildComparisonCard(record);
  if (typeof record.source !== "string" || !record.source.trim())
    throw new RangeError("The exact source is required for a comparison report");
  let replay;
  try { replay = playgroundShareUrl(record.source, record.page); }
  catch { /* Oversized source still gets a complete offline report. */ }
  const replayAction = replay ?
    `<a class="replay" href="${html(replay)}" rel="noreferrer noopener">Open editable source ↗</a>` :
    `<span class="replay unavailable">Source is too long for a replay link; copy it from this report.</span>`;
  const checkerUrl = new URL("./check-run.html", record.page).href;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>ĀML comparison · local run</title><style>
:root{color-scheme:dark;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;--ink:#f2f9fa;--muted:#bad0d9;--line:#557483;--cyan:#83edec;--gold:#f5cc7e}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:radial-gradient(circle at 95% 0,#174550,transparent 38rem),#071421}main{width:min(1140px,calc(100% - 34px));margin:0 auto;padding:42px 0 70px}
.eyebrow{color:var(--gold);font:800 .7rem ui-monospace,monospace;letter-spacing:.13em}h1{margin:10px 0 6px;font-size:clamp(2.1rem,5vw,4.4rem);line-height:1.05;letter-spacing:-.045em}h2{font-size:1.45rem}p{color:var(--muted)}.lead{max-width:690px;font-size:1.07rem}.meta{display:flex;gap:9px;flex-wrap:wrap;margin:22px 0 26px}.meta span{border:1px solid var(--line);border-radius:999px;padding:6px 10px;color:#d7e9eb;font:.7rem ui-monospace,monospace}
.visual{padding:14px;border:1px solid #638b94;border-radius:18px;background:#091e2b;box-shadow:0 25px 70px #0006}.visual svg{display:block;width:100%;height:auto;border-radius:10px}.visual figcaption{margin-top:9px;color:var(--muted);font-size:.75rem;text-align:center}.gates{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.gate{min-width:0;padding:22px;border:1px solid #b0798a;border-radius:17px;background:#271b2b}.gate.allow{border-color:#7fb99d;background:#102b32}.gate-top{display:flex;justify-content:space-between;gap:10px;color:var(--gold);font:.72rem ui-monospace,monospace;letter-spacing:.08em}.gate-top strong{color:#ffacc0}.gate.allow .gate-top strong{color:#a9f1c0}.gate h3{margin:13px 0 2px;font-size:1.4rem;overflow-wrap:anywhere}.element{margin:0;color:#fff;font-size:1.05rem;font-weight:750;overflow-wrap:anywhere}.purpose{margin:4px 0 17px;font-size:.85rem;overflow-wrap:anywhere}.rule{display:flex;align-items:baseline;gap:9px;flex-wrap:wrap;border-top:1px solid var(--line);padding-top:15px}.rule span:first-child{width:100%;color:var(--gold);font:.65rem ui-monospace,monospace;letter-spacing:.1em}.rule b{font:900 1.4rem ui-monospace,monospace}.rule span:last-child{color:var(--muted);font-size:.8rem}.result{margin:16px 0 0;font-size:.8rem}.result b{color:#fff}.evidence{margin-top:30px;padding:24px;border:1px solid var(--line);border-radius:16px;background:#0c2230}.evidence h2{margin:0 0 10px}.hash{display:block;padding:13px;border:1px solid #4f7785;border-radius:9px;background:#061620;color:var(--cyan);font:.75rem/1.5 ui-monospace,monospace;overflow-wrap:anywhere}.replay{display:inline-block;margin:18px 0 5px;border:1px solid var(--cyan);border-radius:9px;padding:10px 14px;background:#153a44;color:var(--cyan);font-weight:800;text-decoration:none}.replay.unavailable{color:var(--muted);border-color:var(--line);background:none;font-size:.78rem}.checker{display:block;margin:4px 0 18px;color:var(--gold);font-size:.84rem;font-weight:800}details{margin-top:12px;border:1px solid var(--line);border-radius:10px;background:#071924}summary{cursor:pointer;padding:13px 16px;color:var(--cyan);font-weight:750}pre{max-height:400px;margin:0;padding:17px;overflow:auto;border-top:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;color:#d9eeee;font:12px/1.6 ui-monospace,monospace}.note{margin:22px 0 0;padding-top:17px;border-top:1px solid var(--line);font-size:.8rem}a:focus-visible,summary:focus-visible{outline:3px solid var(--gold);outline-offset:3px}@media(max-width:660px){.gates{grid-template-columns:1fr}main{padding-top:25px}.evidence{padding:18px}}@media print{:root{color-scheme:light}body{background:white;color:#102431}main{width:100%;padding:0}.visual,.gate,.gate.allow,.evidence{background:white;color:#102431;box-shadow:none}.gate-top strong,.gate.allow .gate-top strong,.rule b,.result b{color:#102431}p,.purpose,.rule span:last-child,.note{color:#344854}.visual{break-inside:avoid}.gate{break-inside:avoid}.hash,pre{background:#fff;color:#102431}details{break-inside:avoid}}
</style></head><body><main>
<span class="eyebrow">ĀML™ / LOCAL COMPARISON REPORT</span><h1>A run you can inspect.</h1>
<p class="lead">Two project browser gates emitted events matching the compiler decisions for the exact source below. The numbers are author-declared prototype inputs.</p>
<div class="meta"><span>2 / 2 GATES MATCHED</span><span>UNSIGNED PROJECT SELF-CHECK</span><span>${html(record.generated_at || "Time not recorded")}</span></div>
<figure class="visual">${card}<figcaption>The visual card and the records below describe the same local run.</figcaption></figure>
<section aria-labelledby="decision-heading"><h2 id="decision-heading">The declared rule, gate by gate</h2><div class="gates">${record.gates.map((gate, index) => gateRow(gate, String(index + 1).padStart(2, "0"))).join("")}</div></section>
<section class="evidence" aria-labelledby="evidence-heading"><h2 id="evidence-heading">Inspect the evidence</h2><p>The SHA-256 identifies the exact source text in this file. It does not authenticate the browser run.</p><code class="hash">SOURCE SHA-256 · ${html(record.source_sha256)}</code>
${replayAction}<p>The replay link contains the full source in its URL fragment. Review it before sharing; never put secrets in source.</p>
<a class="checker" href="${html(checkerUrl)}" rel="noreferrer noopener">Recheck this run ↗</a><p>Copy the full local run JSON below into the browser checker. A consistency check cannot authenticate this file.</p>
<details><summary>Exact ĀML source</summary><pre>${html(record.source)}</pre></details>
<details><summary>Full local run JSON</summary><pre>${html(JSON.stringify(record, null, 2))}</pre></details>
<p class="note">This offline file is an unsigned project-authored self-check. The gate outcomes are based on declared values and this prototype rule. It does not independently validate the declarations, wording, attention, restoration, wellbeing, or production behavior.</p></section>
</main></body></html>`;
}
