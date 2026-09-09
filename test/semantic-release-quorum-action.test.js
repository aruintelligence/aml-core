import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const action = fs.readFileSync("actions/semantic-release-quorum/action.yml", "utf8");

test("semantic release quorum Action passes user paths through environment variables", () => {
  assert.ok(action.includes("AML_PROOF_FILE: ${{ inputs.proof-file }}"));
  assert.ok(action.includes("AML_ENDORSEMENTS_FILE: ${{ inputs.endorsements-file }}"));
  assert.ok(action.includes("AML_POLICY_FILE: ${{ inputs.policy-file }}"));
  assert.ok(action.includes("AML_POLICY_SHA256: ${{ inputs.policy-sha256 }}"));
  const runBody = action.slice(action.indexOf("      run: |"));
  assert.equal(runBody.includes("node \"$GITHUB_ACTION_PATH/../../bin/aml-release-quorum.js\" ${{"), false);
  assert.ok(runBody.includes('ARGS=(verify "$AML_PROOF_FILE" "$AML_ENDORSEMENTS_FILE" "$AML_POLICY_FILE")'));
});

test("semantic release quorum Action exports only verified scalar outputs with delimiter-safe encoding", () => {
  assert.ok(action.includes("if (result.verified !== true) process.exit(1)"));
  assert.ok(action.includes("crypto.randomBytes(16)"));
  assert.ok(action.includes("<<${delimiter}"));
  assert.ok(action.includes("valid_trusted_endorsements: result.valid_trusted_endorsements"));
  assert.ok(action.includes("policy_sha256: result.policy_sha256"));
});
