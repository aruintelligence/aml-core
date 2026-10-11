#!/usr/bin/env node
// Actual JS/Python plan bytes, plus the pre-fix Python lexical-key baseline.
// Generated tests are deterministic project evidence, not a formal proof.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { planAction } from "../pilots/action-boundary/boundary.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const digest = value => crypto.createHash("sha256").update(value, "utf8").digest("hex");
const policy = { protocol: "aml-action-policy/1", rules: [{ tool: "simulated.send", effect: "send",
  resource: "mailbox:example", requires_approval: true }] };
const proposal = args => ({ protocol: "aml-proposed-action/1", tool: "simulated.send", effect: "send",
  resource: "mailbox:example", purpose: "compare canonical bytes", arguments: args });
const named = [
  ["two-numeric-keys", "Numeric-looking keys", { "10": "ten", "2": "two" }],
  ["nested-numeric-keys", "A nested object", { data: { "11": "eleven", "3": "three", a: "letter" } }],
  ["zero-leading-zero", "Zero and leading zero", { "10": "ten", "0": "zero", "01": "ordinary" }],
  ["uint32-edge", "The 32-bit edge", { "4294967294": "last index", "4294967295": "ordinary", "10": "ten", "2": "two" }],
  ["array-object", "An object inside an array", { items: [{ "10": 10, "2": 2 }] }],
  ["non-index-forms", "Lookalikes that are not indices", { "01": "leading", "1.0": "decimal", "-1": "negative", "4294967295": "too large" }],
  ["ordinary-keys", "Ordinary names", { zebra: "z", alpha: "a" }]
];
const cases = named.map(([id, title, args]) => ({ id, title, proposal: proposal(args), policy }));
let state = 0x0a11ce22;
function random() {
  state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
  return state >>> 0;
}
const pool = ["0", "1", "2", "3", "10", "11", "20", "01", "00", "4294967294", "4294967295",
  "-1", "1.0", "alpha", "zeta", "é", "__proto__"];
const values = [0, 1, 42, true, false, "plain", "café", "😀", "line\nbreak"];
for (let i = 0; i < 512; i++) {
  const args = Object.create(null);
  if (i % 3 === 0) { args["2"] = "two"; args["10"] = "ten"; }
  for (let j = 0, n = 2 + random() % 6; j < n; j++) args[pool[random() % pool.length]] = values[random() % values.length];
  if (i % 4 === 0) args.nested = { "11": "eleven", "3": "three", note: "nested" };
  if (i % 7 === 0) args.items = [{ "20": 20, "4": 4 }];
  cases.push({ id: `generated-${String(i + 1).padStart(3, "0")}`, proposal: proposal(args), policy });
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-key-order-"));
let python;
try {
  const file = path.join(temp, "cases.json");
  fs.writeFileSync(file, JSON.stringify({ cases }));
  const run = spawnSync("python3", [path.join(root, "pilots/action-boundary/plan-python-batch.py"), file],
    { encoding: "utf8", timeout: 15000, maxBuffer: 4 * 1024 * 1024 });
  if (run.error || run.status !== 0) throw new Error(`Python batch failed: ${run.error?.message || run.stderr}`);
  python = JSON.parse(run.stdout);
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
assert.equal(python.protocol, "aml-action-key-order-batch/1");
assert.equal(python.cases.length, cases.length);
const rows = cases.map((item, index) => {
  const py = python.cases[index];
  assert.equal(py.id, item.id);
  const wire = canonicalJSONStringify(item.proposal);
  const js = planAction(item.proposal, item.policy);
  const current_agreement = py.python_wire === wire && py.python_plan.proposal_sha256 === js.proposal_sha256 &&
    py.python_plan.decision === js.decision && py.python_plan.reason === js.reason;
  if (!current_agreement) throw new Error(`Cross-runtime divergence: ${item.id} JS=${js.proposal_sha256} Python=${py.python_plan.proposal_sha256}`);
  return { id: item.id, title: item.title, args: item.proposal.arguments,
    javascript: { wire, digest: js.proposal_sha256 },
    previous_python: { wire: py.legacy_wire, digest: py.legacy_digest,
      matched: py.legacy_digest === js.proposal_sha256 },
    fixed_python: { wire: py.python_wire, digest: py.python_plan.proposal_sha256,
      matched: current_agreement } };
});
const report = { protocol: "aml-action-key-order-regression/1",
  provenance: "project-maintained JavaScript and separate Python process; previous Python lexical sort replayed",
  previous_python_source_commit: "96f892913d9d57157dba729eb4db03484a28230b",
  seed: "0x0a11ce22", generated_cases: 512,
  fixture_sha256: digest(JSON.stringify(cases)),
  total_cases: cases.length,
  previous_mismatches: rows.filter(row => !row.previous_python.matched).length,
  fixed_mismatches: rows.filter(row => !row.fixed_python.matched).length,
  selected: rows.slice(0, named.length),
  limits: "Numeric-key regression for the published safe-integer, BMP-key, Unicode-scalar wire subset. Project-authored corpus, not outside validation or universal JSON canonicalization." };
assert.ok(report.previous_mismatches > 0);
assert.equal(report.fixed_mismatches, 0);
if (process.argv.includes("--check")) {
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, "docs/action-key-order-report.json"), "utf8")), report);
  console.log(`Verified ${report.total_cases} JS/Python cases; ${report.previous_mismatches} prior mismatches, 0 now`);
} else {
  console.log(JSON.stringify(report, null, 2));
}
