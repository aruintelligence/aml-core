import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runLocalProviderRecovery } from "../pilots/action-boundary/local-provider-recovery.mjs";

test("lost acknowledgment remains uncertain until a separate provider record is read", async () => {
  const report = await runLocalProviderRecovery({ mode: "lost_ack" });
  assert.equal(report.host_before_recovery, "outcome_uncertain");
  assert.equal(report.host_after_recovery, "completed");
  assert.equal(report.provider_record_found, true);
  assert.equal(report.provider_effect_count, 1);
  assert.equal(report.independent_confirmation, false);
  assert.equal(report.retry_attempted, false);
  assert.equal(report.replay_accepted, false);
});

test("failure before provider write remains uncertain and cannot be retried with the grant", async () => {
  const report = await runLocalProviderRecovery({ mode: "before_write" });
  assert.equal(report.host_before_recovery, "outcome_uncertain");
  assert.equal(report.host_after_recovery, "outcome_uncertain");
  assert.equal(report.provider_effect_count, 0);
  assert.equal(report.provider_record_found, false);
  assert.equal(report.replay_accepted, false);
  assert.equal(report.retry_attempted, false);
});

test("acknowledged local provider record does not become independent confirmation", async () => {
  const report = await runLocalProviderRecovery({ mode: "ack" });
  assert.equal(report.host_before_recovery, "completed");
  assert.equal(report.host_after_recovery, "completed");
  assert.equal(report.provider_effect_count, 1);
  assert.equal(report.independent_confirmation, false);
});

test("provider refuses a request whose bytes do not match its bound digest", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-provider-mismatch-"));
  try {
    const worker = fileURLToPath(new URL("../pilots/action-boundary/local-provider-worker.mjs", import.meta.url));
    const child = spawnSync(process.execPath, [worker, "ack", directory, crypto.randomUUID(),
      "0".repeat(64), JSON.stringify({ body: "changed" })], { encoding: "utf8" });
    assert.notEqual(child.status, 0);
    assert.equal(fs.readdirSync(directory).length, 0);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
