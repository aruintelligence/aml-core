import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const capabilities = JSON.parse(fs.readFileSync("AML_CAPABILITIES.json", "utf8"));

test("AML capability manifest declares the public v1.2 surface", () => {
  assert.equal(capabilities.version, "1.2.0");
  assert.equal(capabilities.compiler.pure_in_memory_compile, true);
  assert.equal(capabilities.compiler.accountable_intent_execution, true);
  assert.equal(capabilities.policy.policy_composition, true);
  assert.equal(capabilities.policy.runtime_privacy_consent, true);
  assert.equal(capabilities.accountability.execution_receipts, true);
  assert.equal(capabilities.accountability.ed25519_execution_receipt_attestation, true);
  assert.equal(capabilities.tooling.lint, true);
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
