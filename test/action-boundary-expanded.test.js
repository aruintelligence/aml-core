import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkEvidence, sha256Canonical } from "../scripts/verify-action-boundary-expanded.mjs";

const cases = JSON.parse(readFileSync(new URL("../conformance/action-boundary-expanded-cases.json", import.meta.url)));
const receipts = readFileSync(new URL("../conformance/action-boundary-expanded-receipts.jsonl", import.meta.url), "utf8")
  .trim().split("\n").map(JSON.parse);
const byId = id => cases.cases.find(row => row.id === id);
const receiptFor = id => receipts.find(row => row.case_id === id);

test("100 new cases and 100 full evidence receipts retain their exact published inputs", () => {
  assert.equal(cases.existing_case_count, 13);
  assert.equal(cases.cases.length, 100);
  assert.equal(receipts.length, 100);
  for (const [i, row] of cases.cases.entries()) checkEvidence(row, receipts[i]);
});

test("reordered member keys leave the digest intact, while actual field changes do not", () => {
  for (const seed of ["mail", "read", "write", "pay", "delete", "http", "ui"]) {
    const baseline = byId(`${seed}-baseline`);
    const reordered = byId(`${seed}-reordered-keys`);
    assert.equal(baseline.expected.plan.proposal_sha256, reordered.expected.plan.proposal_sha256);
    for (const suffix of ["changed-payload", "changed-resource", "changed-tool", "changed-effect"]) {
      assert.notEqual(baseline.expected.plan.proposal_sha256,
        byId(`${seed}-${suffix}`).expected.plan.proposal_sha256);
    }
  }
});

test("tampering with any bound input or outcome invalidates the published evidence", () => {
  const id = "mail-injected-bcc-stale";
  const row = byId(id);
  for (const mutate of [
    r => { r.proposal.arguments.bcc[0] = "other@example.test"; },
    r => { r.host_policy.rules[0].resource = "outsider@example.test"; },
    r => { r.expected_dispatch_receipt.execution_status = "dispatched"; },
    r => { r.host_fixture.approval_digest_sha256 = "0".repeat(64); }
  ]) {
    const altered = structuredClone(receiptFor(id));
    mutate(altered);
    assert.throws(() => checkEvidence(row, altered));
    const { receipt_sha256, ...body } = altered;
    assert.notEqual(receipt_sha256, sha256Canonical(body));
    altered.receipt_sha256 = sha256Canonical(body);
    assert.throws(() => checkEvidence(row, altered), "a rehashed rewrite must differ from the case manifest");
  }
});

test("scope counterexamples prevent unsupported replay and target-security claims", () => {
  assert.equal(byId("mail-injected-bcc-stale").expected.receipt.execution_status, "blocked");
  assert.equal(byId("mail-injected-bcc-fresh").expected.receipt.execution_status, "dispatched");
  assert.equal(byId("write-changed-call-id-stale").expected.receipt.execution_status, "blocked");
  assert.equal(byId("write-exact-call-id-replay").expected.receipt.execution_status, "dispatched");
  assert.equal(byId("http-argument-target-mismatch").expected.receipt.execution_status, "dispatched");
});
