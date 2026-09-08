import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const capabilities = JSON.parse(fs.readFileSync("AML_CAPABILITIES.json", "utf8"));

test("AML capability manifest declares the public v1.3 surface", () => {
  assert.equal(capabilities.version, "1.3.0");
  assert.equal(capabilities.compiler.pure_in_memory_compile, true);
  assert.equal(capabilities.compiler.accountable_intent_execution, true);
  assert.equal(capabilities.compiler.semantic_diff, true);
  assert.equal(capabilities.compiler.policy_diff, true);
  assert.equal(capabilities.policy.policy_composition, true);
  assert.equal(capabilities.policy.signed_data_only_policy_packs, true);
  assert.equal(capabilities.policy.runtime_privacy_consent, true);
  assert.equal(capabilities.policy.cumulative_attention_accounting, true);
  assert.equal(capabilities.accountability.execution_receipts, true);
  assert.equal(capabilities.accountability.runtime_audit_stream, true);
  assert.equal(capabilities.accountability.attention_ledger, true);
  assert.equal(capabilities.accountability.ed25519_execution_receipt_attestation, true);
  assert.equal(capabilities.tooling.local_markdown_link_integrity_check, true);
  assert.equal(capabilities.verification.browser_core_parity, true);
});

test("capability manifest references existing repository artifacts", () => {
  for (const file of [
    capabilities.entry_points.cli,
    capabilities.entry_points.javascript,
    capabilities.entry_points.browser,
    capabilities.policy.decision_json_schema,
    capabilities.accountability.execution_receipt_schema,
    capabilities.verification.canonical_allow_fixture,
    capabilities.verification.canonical_suppress_fixture
  ]) {
    assert.equal(fs.existsSync(file), true, `${file} should exist`);
  }
});
