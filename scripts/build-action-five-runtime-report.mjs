#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { runReferenceCase } from "../pilots/action-boundary/challenge-reference-adapter.mjs";
import { runWebCryptoCase } from "../docs/action-webcrypto-boundary.js";
import { checkObserved } from "./verify-action-boundary-expanded.mjs";

const root = new URL("../", import.meta.url);
const casesBytes = fs.readFileSync(new URL("conformance/action-boundary-expanded-cases.json", root));
const cases = JSON.parse(casesBytes);
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const sourceHash = file => sha(fs.readFileSync(new URL(file, root)));
const runtimes = [
  ["javascript_node", null],
  ["python_hashlib", ["python3", "pilots/action-boundary/challenge-python-adapter.py"]],
  ["perl_digest_sha", ["perl", "pilots/action-boundary/perl_boundary.pl"]],
  ["python_openssl", ["python3", "pilots/action-boundary/openssl_python_boundary.py"]],
  ["webcrypto_node_host", null]
];
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "aml-five-runtime-"));
const rows = [];
try {
  for (const row of cases.cases) {
    const input = { protocol: "aml-action-challenge-case/1", case_id: row.id,
      proposal: row.proposal, policy: row.policy, host: row.host };
    const file = path.join(temporary, `${row.id}.json`);
    fs.writeFileSync(file, JSON.stringify(input));
    const outcomes = {};
    for (const [name, command] of runtimes) {
      let result;
      if (name === "javascript_node") result = await runReferenceCase(input);
      else if (name === "webcrypto_node_host") result = await runWebCryptoCase(input);
      else {
        const execution = spawnSync(command[0], [command[1], file], {
          cwd: root.pathname, encoding: "utf8", timeout: 5000, maxBuffer: 256 * 1024
        });
        assert.equal(execution.status, 0, `${row.id} ${name}: ${execution.stderr || execution.error}`);
        result = JSON.parse(execution.stdout.trim());
      }
      checkObserved(row, result);
      outcomes[name] = { proposal_sha256: result.plan.proposal_sha256,
        decision: result.plan.decision, reason: result.plan.reason,
        gate_outcome: result.tool_calls === 1 ? "ALLOW" : "SUPPRESS",
        execution_status: result.receipt.execution_status,
        receipt_reason: result.receipt.reason,
        tool_calls: result.tool_calls };
    }
    assert.deepEqual(new Set(Object.values(outcomes).map(JSON.stringify)).size, 1, row.id);
    rows.push({ case_id: row.id, outcomes });
  }
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
const report = {
  protocol: "aml-action-five-runtime-matrix/1",
  scope: "project-maintained simulated challenge implementations, not independent outside parties",
  browser_runtime_limit: "WebCrypto-compatible ES module executed under Node WebCrypto; browser execution is not claimed by this report.",
  cases_file_sha256: sha(casesBytes),
  source_sha256: {
    javascript_node: sourceHash("pilots/action-boundary/boundary.mjs"),
    python_hashlib: sourceHash("pilots/action-boundary/python_boundary.py"),
    perl_digest_sha: sourceHash("pilots/action-boundary/perl_boundary.pl"),
    python_openssl: sourceHash("pilots/action-boundary/openssl_python_boundary.py"),
    webcrypto_node_host: sourceHash("docs/action-webcrypto-boundary.js")
  },
  case_count: rows.length,
  matches_by_runtime: Object.fromEntries(runtimes.map(([name]) => [name, rows.length])),
  rows
};
const text = JSON.stringify(report, null, 2) + "\n";
const out = new URL("docs/action-five-runtime-report.json", root);
const mode = process.argv[2];
if (mode === "--write") fs.writeFileSync(out, text);
else if (mode === "--check") assert.equal(fs.readFileSync(out, "utf8"), text,
  "Five-runtime report is stale");
else if (mode !== undefined) throw new Error("Usage: node scripts/build-action-five-runtime-report.mjs [--write|--check]");
console.log(JSON.stringify({ cases: rows.length, matches: report.matches_by_runtime,
  report_sha256: sha(text), first_proposal_sha256: rows[0].outcomes.javascript_node.proposal_sha256 }));
