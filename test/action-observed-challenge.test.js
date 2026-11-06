import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const runner = path.join(root, "scripts/run-action-observed-challenge.mjs");
const run = args => spawnSync(process.execPath, [runner, ...args], {
  cwd: root, encoding: "utf8", timeout: 120_000, maxBuffer: 2 * 1024 * 1024
});

test("runner observes reference callbacks on published and seeded cases", () => {
  const process = run(["--self-test", "--probes", "--probe-seed",
    "00112233445566778899aabbccddeeff"]);
  assert.equal(process.status, 0, process.stderr);
  const report = JSON.parse(process.stdout);
  assert.equal(report.protocol, "aml-action-observed-challenge-report/2");
  assert.equal(report.passed, true);
  assert.equal(report.cases.length, 19);
  assert.equal(report.probe_case_count, 6);
  assert.equal(report.cases.find(item => item.id === "approved-send").observed_callback_count, 1);
  assert.equal(report.cases.find(item => item.id === "changed-destination").observed_callback_count, 0);
  assert.equal(report.cases.find(item => item.id === "dispatch-uncertain").observed_callback_count, 1);
});

test("fabricated tool_calls cannot pass runner-owned observation", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-false-observer-"));
  try {
    const vectors = JSON.parse(fs.readFileSync(path.join(root, "pilots/action-boundary/vectors.json")));
    const digest = vectors.cases.find(item => item.name === "approved_route").proposal_sha256;
    const adapter = path.join(directory, "fake.mjs");
    fs.writeFileSync(adapter, `import fs from "node:fs";
const input = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
console.log(JSON.stringify({protocol:"aml-action-boundary-result/1",
  plan:{protocol:"aml-action-plan/1",proposal_sha256:"${digest}",decision:"requires_approval",reason:"exact_rule"},
  receipt:{protocol:"aml-action-dispatch/1",proposal_sha256:"${digest}",policy_decision:"requires_approval",execution_status:"dispatched",reason:"host_dispatch_returned"},
  tool_calls:1,executed_proposal:input.proposal}));\n`);
    const child = run(["--case", "approved-send", "--", process.execPath, adapter]);
    assert.equal(child.status, 1, child.stderr);
    const report = JSON.parse(child.stdout);
    assert.deepEqual(report.cases[0].failures, ["observed_callback_count", "observed_proposal"]);
    assert.equal(report.cases[0].observed_callback_count, 0);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("a denied case fails when the adapter calls the local provider anyway", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-denied-observer-"));
  try {
    const vectors = JSON.parse(fs.readFileSync(path.join(root, "pilots/action-boundary/vectors.json")));
    const digest = vectors.cases.find(item => item.name === "changed_destination").proposal_sha256;
    const adapter = path.join(directory, "unauthorized.mjs");
    fs.writeFileSync(adapter, `import fs from "node:fs";
const input = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
await fetch(input.host.observed_callback.url, {method:"POST", headers:{"content-type":"application/json",
  "x-aml-challenge-token":input.host.observed_callback.token}, body:JSON.stringify(input.proposal)});
console.log(JSON.stringify({protocol:"aml-action-boundary-result/1",
  plan:{protocol:"aml-action-plan/1",proposal_sha256:"${digest}",decision:"deny",reason:"no_exact_rule"},
  receipt:{protocol:"aml-action-dispatch/1",proposal_sha256:"${digest}",policy_decision:"deny",execution_status:"blocked",reason:"no_exact_rule"},
  tool_calls:0,executed_proposal:null}));\n`);
    const child = run(["--case", "changed-destination", "--", process.execPath, adapter]);
    assert.equal(child.status, 1, child.stderr);
    const report = JSON.parse(child.stdout);
    assert.deepEqual(report.cases[0].failures, ["observed_callback_count", "observed_proposal"]);
    assert.equal(report.cases[0].observed_callback_count, 1);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
