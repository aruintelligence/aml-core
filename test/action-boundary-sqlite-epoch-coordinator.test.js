import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createFileRevocationHandoff } from "../pilots/action-boundary/file-revocation-handoff.mjs";
import { createSqliteEpochCoordinator } from "../pilots/action-boundary/sqlite-epoch-coordinator.mjs";

const script = fileURLToPath(new URL("../pilots/action-boundary/sqlite-epoch-coordinator.py", import.meta.url));
const context = () => ({ tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a",
  audience: "local-record", tool: "write_record", policy: { revision: 1 },
  preparedRequest: { destination: "fixture:outbox", body: "approved" } });
const hex = char => char.repeat(64);
async function fixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aml-sqlite-coordinator-"));
  const authority = path.join(root, "authority");
  const coordinatorDir = path.join(root, "coordinator");
  fs.mkdirSync(coordinatorDir, { mode: 0o700 });
  const database = path.join(coordinatorDir, "claims.sqlite");
  const epochAnchor = createSqliteEpochCoordinator({ database });
  try { epochAnchor.initialize(); return await run({ root, authority, database, epochAnchor }); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}
function direct(database, action, fields = {}) {
  return { protocol: "aml-sqlite-epoch-test/1", action, ...fields };
}
function runDirect(database, request) {
  const child = spawnSync("python3", [script, database], {
    input: JSON.stringify(request), encoding: "utf8", timeout: 20_000 });
  return { status: child.status, output: child.status === 0 ? JSON.parse(child.stdout) : null };
}
function concurrent(database, request) {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [script, database], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", data => { stdout += data; });
    child.stderr.on("data", data => { stderr += data; });
    child.on("error", reject);
    child.on("close", code => code === 0 ? resolve(JSON.parse(stdout)) : reject(Error(stderr)));
    child.stdin.end(JSON.stringify(request));
  });
}

test("retained SQLite claim rejects a restored local authority snapshot", async () => {
  await fixture(async ({ root, authority, epochAnchor }) => {
    const host = createFileRevocationHandoff({ directory: authority, epochAnchor });
    const grant = host.issue(context(), { operationId: "host-intent-sqlite-001" });
    const snapshot = path.join(root, "before-claim");
    fs.cpSync(authority, snapshot, { recursive: true });
    let callbacks = 0;
    const first = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { callbacks++; return "local callback"; } });
    assert.equal(first.status, "returned");
    assert.equal(epochAnchor.inspect().claims, 1);
    fs.renameSync(authority, path.join(root, "after-claim"));
    fs.renameSync(snapshot, authority);
    const restarted = createFileRevocationHandoff({ directory: authority, epochAnchor });
    const replay = await restarted.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } });
    assert.deepEqual([replay.status, replay.reason, replay.dispatch_count, callbacks],
      ["blocked", "external_claim_or_epoch_rejected", 0, 1]);
  });
});

test("separate coordinator processes consume one claim key once", async () => {
  await fixture(async ({ database, epochAnchor }) => {
    const request = direct(database, "claim", { claim_protocol: "aml-file-authority-external-claim/2",
      claim_key_sha256: hex("a"), binding_sha256: hex("b"), issuer_sha256: hex("c"), epoch: 0 });
    const results = await Promise.all(Array.from({ length: 8 }, () => concurrent(database, request)));
    assert.equal(results.filter(result => result.accepted).length, 1);
    assert.equal(epochAnchor.inspect().claims, 1);
  });
});

test("concurrent revocation and claim serialize at one coordinator transaction", async () => {
  await fixture(async ({ database, epochAnchor }) => {
    const issuer_sha256 = hex("c");
    const claim = direct(database, "claim", { claim_protocol: "aml-file-authority-external-claim/2",
      claim_key_sha256: hex("a"), binding_sha256: hex("b"), issuer_sha256, epoch: 0 });
    const revoke = direct(database, "advance", { epoch_protocol: "aml-file-authority-external-epoch/1",
      issuer_sha256, expected_epoch: 0, next_epoch: 1 });
    const [claimResult, revokeResult] = await Promise.all([
      concurrent(database, claim), concurrent(database, revoke)
    ]);
    assert.equal(revokeResult.accepted, true);
    assert.equal(epochAnchor.inspect().epochs, 1);
    assert.equal(epochAnchor.inspect().claims, Number(claimResult.accepted));
    assert.equal(runDirect(database, claim).output.accepted, false);
  });
});

test("revocation epoch rejects stale claims and restored unspent authority", async () => {
  await fixture(async ({ root, authority, epochAnchor }) => {
    const host = createFileRevocationHandoff({ directory: authority, epochAnchor });
    const grant = host.issue(context(), { operationId: "host-intent-sqlite-epoch" });
    const snapshot = path.join(root, "before-revoke");
    fs.cpSync(authority, snapshot, { recursive: true });
    assert.equal((await host.revokeIssuerAnchored(context())).epoch, 1);
    fs.renameSync(authority, path.join(root, "after-revoke"));
    fs.renameSync(snapshot, authority);
    let callbacks = 0;
    const restarted = createFileRevocationHandoff({ directory: authority, epochAnchor });
    const result = await restarted.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } });
    assert.deepEqual([result.status, result.dispatch_count, callbacks], ["blocked", 0, 0]);
  });
});

test("lost acknowledgment after committed claim stays spent on retry", async () => {
  await fixture(({ database, epochAnchor }) => {
    const request = direct(database, "claim", { claim_protocol: "aml-file-authority-external-claim/2",
      claim_key_sha256: hex("a"), binding_sha256: hex("b"), issuer_sha256: hex("c"), epoch: 0 });
    assert.equal(runDirect(database, { ...request, fault: "exit_after_commit" }).status, 75);
    assert.equal(epochAnchor.inspect().claims, 1);
    assert.deepEqual(runDirect(database, request), { status: 0, output: { accepted: false } });
  });
});

test("missing coordinator database blocks callback instead of recreating authority", async () => {
  await fixture(async ({ authority, database, epochAnchor }) => {
    const host = createFileRevocationHandoff({ directory: authority, epochAnchor });
    const grant = host.issue(context());
    fs.rmSync(database);
    let callbacks = 0;
    const result = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } });
    assert.deepEqual([result.status, result.dispatch_count, callbacks], ["indeterminate", 0, 0]);
  });
});

test("joint rollback of authority and coordinator still permits duplicate callback", async () => {
  await fixture(async ({ root, authority, database, epochAnchor }) => {
    const host = createFileRevocationHandoff({ directory: authority, epochAnchor });
    const grant = host.issue(context(), { operationId: "host-intent-joint-rollback" });
    const oldAuthority = path.join(root, "old-authority");
    const oldDatabase = path.join(root, "old-coordinator.sqlite");
    fs.cpSync(authority, oldAuthority, { recursive: true });
    fs.copyFileSync(database, oldDatabase);
    let callbacks = 0;
    assert.equal((await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } })).status, "returned");
    fs.renameSync(authority, path.join(root, "spent-authority"));
    fs.renameSync(oldAuthority, authority);
    fs.copyFileSync(oldDatabase, database);
    const restarted = createFileRevocationHandoff({ directory: authority, epochAnchor });
    assert.equal((await restarted.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } })).status, "returned");
    assert.equal(callbacks, 2); // The two stores must have independent retention.
  });
});
