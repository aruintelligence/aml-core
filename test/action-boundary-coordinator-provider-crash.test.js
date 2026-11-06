import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const worker = fileURLToPath(new URL("../pilots/action-boundary/coordinator-provider-crash-worker.mjs", import.meta.url));
function scenario(fault) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-coordinator-crash-"));
  try {
    const start = spawnSync(process.execPath, [worker, "start", directory, fault],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(start.status, 77, start.stderr || start.error?.message);
    const recover = spawnSync(process.execPath, [worker, "recover", directory],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(recover.status, 0, recover.stderr || recover.error?.message);
    return JSON.parse(recover.stdout);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
for (const [fault, present] of [["after_commit", true], ["before_commit", false]]) {
  test(`host crash inside callback, provider ${fault}`, () => {
    const result = scenario(fault);
    assert.equal(result.replay_status, "indeterminate");
    assert.equal(result.replay_reason, "authority_busy_or_crashed");
    assert.equal(result.callbacks, 0);
    assert.equal(result.coordinator_claims, 1);
    assert.equal(result.provider_record_matches, present);
    assert.equal(result.provider_record_absent, !present);
    assert.equal(result.provider_signature_result, present ? "PROVIDER_REPORTED" : "INCOMPLETE");
    assert.equal(result.host_outcome, "unknown");
    assert.equal(result.independent_confirmation, false);
    assert.equal(result.retry_attempted, false);
  });
}
