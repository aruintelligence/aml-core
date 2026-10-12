#!/usr/bin/env node
// Deterministic, project-authored counterexample: copying public answers can
// pass the fixed suite, but not fresh proposal and policy transformations.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { prepareCase, checkCase } from "../conformance/action-boundary-challenge-core.js";
import { generateActionProbes } from "../conformance/action-boundary-probes.js";
import { cannedAnswer } from "../test/fixtures/canned-action-adapter.mjs";
import { runReferenceCase } from "../pilots/action-boundary/challenge-reference-adapter.mjs";

const seed = "0123456789abcdef0123456789abcdef";
const root = new URL("../", import.meta.url);
const manifestBytes = fs.readFileSync(new URL("conformance/action-boundary-challenge.json", root));
const manifest = JSON.parse(manifestBytes);
const vectorBytes = fs.readFileSync(new URL(manifest.vectors_file, root));
const originalVectors = JSON.parse(vectorBytes);
const { rows: probes, vectors } = generateActionProbes(manifest, originalVectors, seed);
const rows = [...manifest.cases, ...probes];
const sha256 = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const results = [];
for (const row of rows) {
  const input = prepareCase(row, vectors);
  const canned = cannedAnswer(input);
  const reference = await runReferenceCase(input);
  const invocation = { status: 0 };
  const cannedFailures = checkCase(row, canned, invocation, vectors);
  const referenceFailures = checkCase(row, reference, invocation, vectors);
  assert.deepEqual(referenceFailures, [], row.id);
  results.push({ id: row.id, kind: probes.includes(row) ? "seeded_probe" : "published_case",
    expected_decision: row.expected.decision, expected_status: row.expected.status,
    canned_passed: cannedFailures.length === 0, canned_failures: cannedFailures,
    reference_passed: true });
}
assert.equal(results.filter(row => row.kind === "published_case" && row.canned_passed).length, 13);
assert.equal(results.filter(row => row.kind === "seeded_probe" && row.canned_passed).length, 0);
const report = { protocol: "aml-action-probe-comparison/1", seed,
  challenge_sha256: sha256(manifestBytes), vectors_sha256: sha256(vectorBytes),
  published_case_count: manifest.cases.length, probe_count: probes.length,
  fixed_canned_passes: 13, expanded_canned_passes: 13,
  expanded_reference_passes: 19, cases: results,
  claim_boundary: "Project-authored seeded probes expose this deliberately canned case-ID adapter. Passing them cannot prove an implementation is independent, complete, or production safe." };
const json = JSON.stringify(report, null, 2) + "\n";
const esc = value => String(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const cards = results.filter(row => row.kind === "seeded_probe").map((row, index) =>
  `<article class="probe"><span>PROBE ${String(index + 1).padStart(2, "0")} / ${esc(row.id)}</span><h3>${esc(row.id.replaceAll("-", " "))}</h3><p>Expected: <b>${esc(row.expected_decision)} / ${esc(row.expected_status)}</b></p><div><strong>CANNED FAIL</strong><strong>REFERENCE PASS</strong></div><small>${esc(row.canned_failures.join(" · "))}</small></article>`).join("\n");
const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#06121d"><meta name="description" content="A fixed thirteen-case adapter can copy answers. Six seeded follow-up probes expose it in a project-authored comparison."><title>When 13/13 is a false signal · ĀML</title><style>
:root{color-scheme:dark;--bg:#06121d;--ink:#f4f8fc;--muted:#b9cbd6;--cyan:#83ebeb;--red:#ff929e;--green:#a3f2b5;--line:#36546a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#1a596077,transparent 42rem),radial-gradient(circle at 4% 40%,#532a3f66,transparent 36rem),var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}.wrap{max-width:1180px;margin:auto;padding:0 24px}a{color:var(--cyan)}a:focus-visible{outline:3px solid #ffd285;outline-offset:4px}.nav{padding:22px 0;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:18px;flex-wrap:wrap}.nav b{letter-spacing:.13em}.nav a{text-decoration:none}.hero{padding:65px 0 42px;max-width:900px}.kicker,.probe span{font:800 .74rem ui-monospace,monospace;letter-spacing:.14em;color:var(--cyan)}h1{font-size:clamp(3.25rem,7vw,6.8rem);letter-spacing:-.075em;line-height:.94;margin:18px 0 25px}h1 em{font-style:normal;color:var(--red)}.hero p{color:#d4e2e9;font-size:1.15rem;max-width:740px}.hero small{color:var(--muted)}.scores{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:15px 0 52px}.score{border:1px solid var(--line);background:#102638;border-radius:18px;padding:23px}.score:nth-child(2){border-color:#aa6871;background:#392b38}.score:nth-child(3){border-color:#64a986;background:#193a37}.score span{font:800 .73rem ui-monospace,monospace;letter-spacing:.12em;color:var(--muted)}.score strong{display:block;font-size:clamp(2.5rem,6vw,5rem);line-height:1.15;letter-spacing:-.06em}.score:nth-child(2) strong{color:var(--red)}.score:nth-child(3) strong{color:var(--green)}.score p{margin:5px 0 0;color:#d2e0e8;font-size:.88rem}.arrow{font-size:1.8rem;color:var(--cyan)}.section-head{display:flex;justify-content:space-between;gap:30px;align-items:end}.section-head h2{font-size:clamp(2.1rem,4vw,3.5rem);line-height:1;letter-spacing:-.05em;margin:0}.section-head p{max-width:480px;color:var(--muted);margin:0}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:13px;margin:22px 0 44px}.probe{background:linear-gradient(135deg,#17384a,#0e2231);border:1px solid var(--line);border-radius:17px;padding:22px}.probe h3{text-transform:capitalize;font-size:1.4rem;letter-spacing:-.04em;margin:8px 0}.probe p{color:var(--muted);margin:0 0 16px}.probe p b{color:var(--ink)}.probe div{display:flex;gap:9px;flex-wrap:wrap}.probe strong{font:850 .74rem ui-monospace,monospace;border-radius:99px;padding:6px 10px;color:var(--red);background:#673341}.probe strong+strong{color:var(--green);background:#285447}.probe small{display:block;color:var(--muted);margin-top:13px;overflow-wrap:anywhere}.method{border:1px solid #638b98;border-radius:18px;padding:25px;background:#122c3b;margin:0 0 42px}.method h2{margin:0 0 7px}.method p{color:#d1e0e7}.method code{overflow-wrap:anywhere;color:var(--cyan)}.method pre{background:#071620;padding:15px;border-radius:10px;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--green)}.foot{border-top:1px solid var(--line);padding:25px 0 50px;color:var(--muted);font-size:.84rem}@media(max-width:800px){.scores,.grid{grid-template-columns:1fr}.section-head{display:block}.section-head p{margin-top:12px}.hero{padding-top:42px}}
</style></head><body><main class="wrap"><nav class="nav"><b>ĀML™ / COUNTERFACTUAL CHALLENGE</b><a href="action-challenge.html">13-case contract ↗</a></nav><header class="hero"><div class="kicker">PROJECT-AUTHORED COUNTEREXAMPLE / SEE THE ANSWERS BREAK</div><h1>13 / 13.<br><em>Still wrong.</em></h1><p>A deliberately canned adapter reads case IDs and copies the published answers. It passes all fixed cases without implementing policy, approval, freezing, or dispatch. Six generated follow-up inputs expose that shortcut.</p><small>Reproducible seed: <code>${seed}</code> · No live tools or outside adapter</small></header><section class="scores" aria-label="Comparison"><div class="score"><span>FIXED SET / CANNED ANSWERS</span><strong>13/13</strong><p>A convincing but shallow pass.</p></div><div class="score"><span>PLUS SIX SEEDED PROBES</span><strong>13/19</strong><p>The same canned adapter fails every new probe.</p></div><div class="score"><span>REFERENCE BOUNDARY</span><strong>19/19</strong><p>Project-maintained execution passes this seed.</p></div></section><section><div class="section-head"><h2>Change the question.<br>Watch the answer.</h2><p>Each probe changes proposal bytes or the exact rule. Expected outcomes are derived from published transformation rules and checked against a fresh reference execution.</p></div><div class="grid">${cards}</div></section><section class="method"><h2>Reproduce it with a fresh seed.</h2><p>The Action now adds six generated probes to every outside adapter run. Its JSON and HTML artifact records the seed and all 19 verdicts. Locally:</p><pre>node scripts/run-action-boundary-challenge.mjs --probes -- ../my-adapter/adapter</pre><p>Repeat one run with <code>--probe-seed ${seed}</code>. The fixed 13-case mode remains available without <code>--probes</code>. <a href="action-probe-report.json">Inspect the exact comparison JSON ↗</a> · <a href="https://github.com/aruintelligence/aml-core/blob/main/publications/ACTION_BOUNDARY_CHALLENGE.md">Read the adapter contract ↗</a>.</p></section><footer class="foot">The transformations and seed are public. Passing all 19 is stronger compatibility evidence than passing the static set, but it cannot prove independence, completeness, safety, authenticated approval, or a real external effect. This comparison is entirely project-authored.</footer></main></body></html>\n`;
for (const [file, content] of [["docs/action-probe-report.json", json], ["docs/action-probe-lab.html", html]]) {
  const target = new URL(file, root);
  if (process.argv.includes("--check")) assert.equal(fs.readFileSync(target, "utf8"), content, file);
  else fs.writeFileSync(target, content);
}
console.log(`Verified ${results.length} cases: canned 13/19, reference 19/19`);
