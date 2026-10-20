#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { runReferenceCase } from "../pilots/action-boundary/challenge-reference-adapter.mjs";

export const sha256Canonical = value => crypto.createHash("sha256")
  .update(canonicalJSONStringify(value), "utf8").digest("hex");

export function checkEvidence(row, receipt) {
  const { receipt_sha256, ...body } = receipt;
  const expected = row.expected;
  assert.equal(row.protocol, "aml-action-expanded-case/1");
  assert.equal(row.receipt_schema, "protocol/action-boundary-evidence-receipt.schema.json");
  assert.equal(body.protocol, "aml-action-boundary-evidence-receipt/1");
  assert.equal(body.case_id, row.id);
  assert.equal(body.provenance, "project-authored deterministic simulated-host fixture");
  assert.deepEqual(body.proposal, row.proposal);
  assert.deepEqual(body.host_policy, row.policy);
  assert.deepEqual(body.host_fixture, row.host);
  assert.deepEqual(body.expected_plan, expected.plan);
  assert.deepEqual(body.expected_dispatch_receipt, expected.receipt);
  assert.equal(body.expected_tool_calls, expected.tool_calls);
  assert.deepEqual(body.expected_executed_proposal, expected.executed_proposal);
  assert.equal(body.proposal_input_sha256, sha256Canonical(row.proposal));
  assert.equal(body.initial_policy_sha256, sha256Canonical(row.policy));
  assert.equal(receipt_sha256, sha256Canonical(body));
  assert.deepEqual(Object.keys(body).sort(), ["protocol", "case_id", "provenance",
    "proposal", "host_policy", "host_fixture", "expected_plan", "expected_dispatch_receipt",
    "expected_tool_calls", "expected_executed_proposal", "proposal_input_sha256",
    "initial_policy_sha256"].sort());
}

export function checkObserved(row, result) {
  assert.equal(result.protocol, "aml-action-boundary-result/1", row.id);
  for (const key of ["plan", "receipt", "tool_calls", "executed_proposal"]) {
    assert.ok(isDeepStrictEqual(result[key], row.expected[key]), `${row.id}: ${key} mismatch\n` +
      `expected ${JSON.stringify(row.expected[key])}\nobserved ${JSON.stringify(result[key])}`);
  }
}

if (process.argv[1] && process.argv[1].endsWith("verify-action-boundary-expanded.mjs")) {
  const mode = process.argv[2];
  if (mode !== undefined && !["--write", "--check"].includes(mode))
    throw new Error("Usage: node scripts/verify-action-boundary-expanded.mjs [--write|--check]");
  const root = new URL("../", import.meta.url);
  const caseBytes = fs.readFileSync(new URL("conformance/action-boundary-expanded-cases.json", root));
  const receiptBytes = fs.readFileSync(new URL("conformance/action-boundary-expanded-receipts.jsonl", root));
  const cases = JSON.parse(caseBytes);
  const receipts = receiptBytes.toString("utf8")
    .trimEnd().split("\n").map(line => JSON.parse(line));
  assert.equal(cases.protocol, "aml-action-expanded-challenge/1");
  assert.equal(cases.existing_case_count, 13);
  assert.ok(cases.cases.length >= 50);
  assert.equal(receipts.length, cases.cases.length);
  assert.equal(new Set(cases.cases.map(row => row.id)).size, cases.cases.length);
  let blocked = 0;
  let callbacks = 0;
  for (const [index, row] of cases.cases.entries()) {
    checkEvidence(row, receipts[index]);
    const input = { protocol: "aml-action-challenge-case/1", case_id: row.id,
      proposal: row.proposal, policy: row.policy, host: row.host };
    const observed = await runReferenceCase(input);
    checkObserved(row, observed);
    blocked += observed.receipt.execution_status === "blocked" ? 1 : 0;
    callbacks += observed.tool_calls;
  }
  const py = spawnSync("python3", [new URL("scripts/verify-action-boundary-expanded.py", root).pathname],
    { cwd: root.pathname, encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 30000 });
  if (py.status !== 0) throw new Error(`Python verifier failed (${py.status}): ${py.stderr || py.stdout}`);
  const pySummary = JSON.parse(py.stdout.trim());
  assert.equal(pySummary.cases, cases.cases.length);
  assert.equal(pySummary.receipts, receipts.length);
  assert.equal(pySummary.blocked, blocked);
  assert.equal(pySummary.callbacks, callbacks);
  const fileHash = path => crypto.createHash("sha256").update(fs.readFileSync(new URL(path, root))).digest("hex");
  const report = { protocol: "aml-action-expanded-verification/1",
    project_authored: true, cases: cases.cases.length, receipts: receipts.length,
    javascript_matched: cases.cases.length, python_matched: pySummary.cases,
    blocked, callbacks, first_receipt_sha256: receipts[0].receipt_sha256,
    last_receipt_sha256: receipts.at(-1).receipt_sha256,
    provenance_sha256: {
      challenge_cases: crypto.createHash("sha256").update(caseBytes).digest("hex"),
      evidence_receipts: crypto.createHash("sha256").update(receiptBytes).digest("hex"),
      evidence_schema: fileHash("protocol/action-boundary-evidence-receipt.schema.json"),
      generator: fileHash("scripts/build-action-boundary-expanded.mjs"),
      javascript_boundary: fileHash("pilots/action-boundary/boundary.mjs"),
      python_boundary: fileHash("pilots/action-boundary/python_boundary.py")
    },
    limits: "Project-authored simulated callbacks; no independent witness, live side effect, authenticated approver, or certified production boundary." };
  const reportText = JSON.stringify(report, null, 2) + "\n";
  const reportUrl = new URL("docs/action-boundary-expanded-report.json", root);
  if (mode === "--write") fs.writeFileSync(reportUrl, reportText);
  if (mode === "--check") assert.equal(fs.readFileSync(reportUrl, "utf8"), reportText);
  process.stdout.write(reportText);
}
