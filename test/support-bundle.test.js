import test from "node:test";
import assert from "node:assert/strict";
import { createAmlSupportBundle, AML_SUPPORT_CONTRACT_FILES } from "../tooling/supportBundle.js";

test("support bundle is deterministic and excludes file contents", () => {
  const first = createAmlSupportBundle();
  const second = createAmlSupportBundle();
  assert.equal(first.protocol, "aml-support-bundle/1");
  assert.equal(first.healthy, true);
  assert.equal(first.contract_set_sha256, second.contract_set_sha256);
  assert.equal(first.contracts.length, AML_SUPPORT_CONTRACT_FILES.length);
  assert.equal(first.contracts.every(item => item.present && typeof item.sha256 === "string" && item.sha256.length === 64), true);
  assert.deepEqual(first.privacy, {
    includes_file_contents: false,
    includes_environment_variables: false,
    includes_credentials: false,
    includes_private_keys: false
  });
  assert.equal(first.generated_at, null);
});
