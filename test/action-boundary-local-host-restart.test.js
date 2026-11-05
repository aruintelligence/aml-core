import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const worker = fileURLToPath(new URL("../pilots/action-boundary/local-host-restart-worker.mjs", import.meta.url));
function scenario(fault) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-host-restart-"));
  try {
    const start = spawnSync(process.execPath, [worker, "start", directory, fault],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(start.status, 77, start.stderr || start.error?.message);
    const saved = JSON.parse(fs.readFileSync(path.join(directory, "host-journal.json"), "utf8"));
    assert.equal(saved.events.at(-1).to, "request_initiated");
    const recovery = spawnSync(process.execPath, [worker, "recover", directory],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(recovery.status, 0, recovery.stderr || recovery.error?.message);
    return JSON.parse(recovery.stdout);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
test("fresh host process reconciles provider record after acknowledgment loss", () => {
  const result = scenario("lost_ack");
  assert.equal(result.host_before_recovery, "outcome_uncertain");
  assert.equal(result.host_after_recovery, "completed");
  assert.equal(result.effect_count, 1);
  assert.equal(result.provider_record_found, true);
  assert.equal(result.replay_accepted, false);
  assert.equal(result.retry_attempted, false);
  assert.equal(result.independent_confirmation, false);
});
test("fresh host process keeps absent provider record uncertain", () => {
  const result = scenario("before_write");
  assert.equal(result.host_before_recovery, "outcome_uncertain");
  assert.equal(result.host_after_recovery, "outcome_uncertain");
  assert.equal(result.effect_count, 0);
  assert.equal(result.provider_record_found, false);
  assert.equal(result.replay_accepted, false);
  assert.equal(result.retry_attempted, false);
});
test("changed journal request bytes fail recovery without another effect", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-host-corrupt-"));
  try {
    const start = spawnSync(process.execPath, [worker, "start", directory, "lost_ack"],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(start.status, 77, start.stderr || start.error?.message);
    const journal = path.join(directory, "host-journal.json");
    const record = JSON.parse(fs.readFileSync(journal, "utf8"));
    record.request_bytes = record.request_bytes.replace("authorized fixture", "altered fixture");
    fs.writeFileSync(journal, JSON.stringify(record));
    const recovery = spawnSync(process.execPath, [worker, "recover", directory],
      { encoding: "utf8", timeout: 30_000 });
    assert.notEqual(recovery.status, 0);
    assert.match(recovery.stderr, /Invalid host journal binding/);
    assert.equal(fs.readdirSync(path.join(directory, "effects")).length, 1);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test("substituted proposal identity cannot inherit another operation's provider completion", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-host-substitute-"));
  try {
    const start = spawnSync(process.execPath, [worker, "start", directory, "lost_ack"],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(start.status, 77, start.stderr || start.error?.message);
    const journal = path.join(directory, "host-journal.json");
    const record = JSON.parse(fs.readFileSync(journal, "utf8"));
    record.proposal_sha256 = "f".repeat(64);
    record.approval.proposal_sha256 = record.proposal_sha256;
    fs.writeFileSync(journal, JSON.stringify(record));
    const recovery = spawnSync(process.execPath, [worker, "recover", directory],
      { encoding: "utf8", timeout: 30_000 });
    assert.notEqual(recovery.status, 0, "recovery must reject an invented proposal digest");
    assert.equal(fs.readdirSync(path.join(directory, "effects")).length, 1);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test("recomputed journal digest cannot replace the issued grant's proposal", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-host-rehash-"));
  try {
    const start = spawnSync(process.execPath, [worker, "start", directory, "lost_ack"],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(start.status, 77, start.stderr || start.error?.message);
    const journal = path.join(directory, "host-journal.json");
    const record = JSON.parse(fs.readFileSync(journal, "utf8"));
    record.proposal_sha256 = "f".repeat(64);
    record.approval.proposal_sha256 = record.proposal_sha256;
    const request = JSON.parse(record.request_bytes);
    request.proposal_sha256 = record.proposal_sha256;
    record.request_bytes = JSON.stringify(request);
    record.request_sha256 = crypto.createHash("sha256").update(record.request_bytes).digest("hex");
    fs.writeFileSync(journal, JSON.stringify(record));
    const recovery = spawnSync(process.execPath, [worker, "recover", directory],
      { encoding: "utf8", timeout: 30_000 });
    assert.notEqual(recovery.status, 0);
    assert.match(recovery.stderr, /Invalid host grant binding/);
    assert.equal(fs.readdirSync(path.join(directory, "effects")).length, 1);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
