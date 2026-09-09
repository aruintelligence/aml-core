import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const action = fs.readFileSync("actions/semantic-release-proof/action.yml", "utf8");
const runner = fs.readFileSync("scripts/semantic-release-gate.js", "utf8");

const outputBindings = [
  ["verified", "verified"],
  ["signer", "signer"],
  ["release-id", "release_id"],
  ["previous-release-id", "previous_release_id"],
  ["before-root", "before_root"],
  ["after-root", "after_root"],
  ["lineage-head", "lineage_head"],
  ["proof-sha256", "proof_sha256"],
  ["semantic-changed", "semantic_changed"],
  ["added", "added"],
  ["removed", "removed"],
  ["changed", "changed"],
  ["unchanged", "unchanged"]
];

test("Semantic Release Gate invokes the canonical release-proof verifier", () => {
  assert.match(action, /name: "ĀML Semantic Release Gate"/);
  assert.match(action, /proof-file:/);
  assert.match(action, /scripts\/semantic-release-gate\.js/);
  assert.match(runner, /verifySemanticReleaseProof/);
  assert.match(runner, /process\.exit\(result\.verified \? 0 : 1\)/);
});

test("Semantic Release Gate exposes every documented trusted output through one verification step", () => {
  for (const [publicName, stepName] of outputBindings) {
    assert.ok(action.includes(`${publicName}:`), `missing action output ${publicName}`);
    assert.ok(action.includes(`steps.verify.outputs.${stepName}`), `missing verifier binding for ${publicName}`);
    assert.ok(runner.includes(`${stepName}:`), `runner does not emit ${stepName}`);
  }
});

test("Semantic Release Gate runner uses verifier-returned authenticated signer rather than proof claim", () => {
  assert.match(runner, /signer:\s*result\.signer/);
  assert.doesNotMatch(runner, /signer:\s*proof\.signer/);
  assert.match(runner, /verified:\s*result\.verified/);
});

test("Semantic Release Gate writes GitHub outputs only through GITHUB_OUTPUT", () => {
  assert.match(runner, /process\.env\.GITHUB_OUTPUT/);
  assert.match(runner, /fs\.appendFileSync\(process\.env\.GITHUB_OUTPUT/);
});
