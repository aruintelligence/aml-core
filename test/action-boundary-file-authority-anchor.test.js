import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createFileAuthorityAnchor, createFileRevocationHandoff } from
  "../pilots/action-boundary/file-revocation-handoff.mjs";
import { createTestingClaimOnce } from
  "../pilots/action-boundary/testing-claim-anchor.mjs";

const input = () => ({ tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a",
  audience: "mail-service", tool: "send_message", policy: { revision: 1 },
  preparedRequest: { to: "team@example.test", body: "Approved" } });
const worker = new URL("../pilots/action-boundary/file-anchor-worker.mjs", import.meta.url).pathname;
const exec = promisify(execFile);
function copyAuthority(directory, snapshot) {
  fs.cpSync(directory, snapshot, { recursive: true });
  fs.chmodSync(snapshot, 0o700);
  for (const child of ["epochs", "grants", "operations", "claimed", "outcomes"]) {
    fs.chmodSync(path.join(snapshot, child), 0o700);
  }
  for (const file of ["checkpoint.json", "clock.json"]) {
    fs.chmodSync(path.join(snapshot, file), 0o600);
  }
  for (const child of ["grants", "operations"]) {
    for (const file of fs.readdirSync(path.join(snapshot, child))) {
      fs.chmodSync(path.join(snapshot, child, file), 0o600);
    }
  }
}
async function fixture(run) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-anchor-test-"));
  const directory = path.join(parent, "authority");
  const anchorDirectory = path.join(parent, "independent-anchor");
  try {
    const anchor = createFileAuthorityAnchor({ directory: anchorDirectory });
    const host = createFileRevocationHandoff({ directory, anchor });
    return await run({ parent, directory, anchorDirectory, anchor, host });
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
}

test("an independent checkpoint advances for issue, claim, and revocation", () =>
  fixture(async ({ directory, anchor, host }) => {
    assert.equal(anchor.read().sequence, 0);
    const grant = host.issue(input(), { operationId: "host-intent-anchored-001" });
    assert.equal(anchor.read().sequence, 1);
    let callbacks = 0;
    const first = await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { callbacks++; return "simulated"; } });
    assert.deepEqual([first.status, callbacks, anchor.read().sequence], ["returned", 1, 2]);
    assert.equal(host.revokeIssuer(input()).epoch, 1);
    assert.equal(anchor.read().sequence, 3);
    const restarted = createFileRevocationHandoff({ directory, anchor:
      createFileAuthorityAnchor({ directory: anchor.directory }) });
    const replay = await restarted.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } });
    assert.equal(replay.dispatch_count, 0);
    assert.equal(callbacks, 1);
    assert.throws(() => createFileRevocationHandoff({ directory }), /authority_anchor_required/);
  }));

test("a separate anchored worker dispatches once and its replay is blocked", () =>
  fixture(async ({ directory, anchorDirectory, anchor, host }) => {
    const grant = host.issue(input(), { operationId: "host-intent-anchored-worker" });
    const first = JSON.parse((await exec(process.execPath,
      [worker, directory, anchorDirectory, grant.grant_id])).stdout);
    const second = JSON.parse((await exec(process.execPath,
      [worker, directory, anchorDirectory, grant.grant_id])).stdout);
    assert.deepEqual([first.status, first.dispatch_count, second.dispatch_count],
      ["returned", 1, 0]);
    assert.equal(fs.readFileSync(path.join(anchorDirectory, "effects.log"), "utf8"), "callback\n");
    assert.equal(anchor.read().sequence, 2);
  }));

test("a restored older authority snapshot fails before any callback in a fresh process", () =>
  fixture(async ({ parent, directory, anchorDirectory, anchor, host }) => {
    const grant = host.issue(input(), { operationId: "host-intent-anchored-002" });
    const snapshot = path.join(parent, "old-snapshot");
    copyAuthority(directory, snapshot);
    let callbacks = 0;
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } })).status, "returned");
    assert.equal(anchor.read().sequence, 2);
    fs.renameSync(directory, path.join(parent, "newer"));
    fs.renameSync(snapshot, directory);
    assert.throws(() => createFileRevocationHandoff({ directory, anchor:
      createFileAuthorityAnchor({ directory: anchor.directory }) }), /authority_anchor_mismatch/);
    const child = JSON.parse((await exec(process.execPath,
      [worker, directory, anchorDirectory, grant.grant_id])).stdout);
    assert.deepEqual([child.reason, child.dispatch_count], ["authority_anchor_mismatch", 0]);
    assert.equal(fs.existsSync(path.join(anchorDirectory, "effects.log")), false);
    assert.equal(callbacks, 1);
  }));

test("a restored unspent grant cannot bypass a revocation absent a spent-claim anchor", () =>
  fixture(async ({ parent, directory, anchorDirectory, anchor, host }) => {
    const grant = host.issue(input(), { operationId: "host-intent-pre-revocation" });
    const snapshot = path.join(parent, "pre-revocation");
    copyAuthority(directory, snapshot);
    assert.equal(host.revokeIssuer(input()).epoch, 1);
    assert.equal(anchor.read().sequence, 2);
    fs.renameSync(directory, path.join(parent, "revoked-authority"));
    fs.renameSync(snapshot, directory);
    const result = JSON.parse((await exec(process.execPath,
      [worker, directory, anchorDirectory, grant.grant_id])).stdout);
    assert.deepEqual([result.reason, result.dispatch_count], ["authority_anchor_mismatch", 0]);
    assert.equal(fs.existsSync(path.join(anchorDirectory, "effects.log")), false);
  }));

test("checkpoint and external one-use claim can gate the same callback", () =>
  fixture(async ({ parent, directory, anchor, host }) => {
    const claimDirectory = path.join(parent, "claims-independent");
    fs.mkdirSync(claimDirectory, { mode: 0o700 });
    const claim = createTestingClaimOnce(claimDirectory);
    const grant = host.issue(input(), { operationId: "host-intent-two-anchors" });
    const combined = createFileRevocationHandoff({ directory, anchor, claimOnce: claim });
    let calls = 0;
    const first = await combined.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { calls++; return true; } });
    const retry = await combined.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([first.status, retry.dispatch_count, calls, anchor.read().sequence],
      ["returned", 0, 1, 2]);
    assert.equal(fs.readdirSync(claimDirectory).length, 1);
  }));

test("a checkpoint mismatch during an awaited external claim stops the callback", () =>
  fixture(async ({ directory, anchor, host }) => {
    const grant = host.issue(input());
    const previous = fs.readFileSync(path.join(directory, "checkpoint.json"));
    const combined = createFileRevocationHandoff({ directory, anchor,
      claimOnce: async () => {
        await Promise.resolve();
        fs.writeFileSync(path.join(directory, "checkpoint.json"), previous);
        return true;
      } });
    let calls = 0;
    const result = await combined.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([result.status, result.dispatch_count, calls], ["indeterminate", 0, 0]);
    assert.equal(anchor.read().sequence, 2);
  }));

test("restoring both the authority and its file anchor permits replay after restart", () =>
  fixture(async ({ parent, directory, anchorDirectory, anchor, host }) => {
    const grant = host.issue(input(), { operationId: "host-intent-both-restored" });
    const oldAuthority = path.join(parent, "old-authority");
    const oldAnchor = path.join(parent, "old-anchor");
    copyAuthority(directory, oldAuthority);
    fs.cpSync(anchorDirectory, oldAnchor, { recursive: true });
    fs.chmodSync(oldAnchor, 0o700);
    fs.chmodSync(path.join(oldAnchor, "checkpoint.json"), 0o600);
    let callbacks = 0;
    assert.equal((await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } })).status, "returned");
    assert.equal(anchor.read().sequence, 2);
    fs.renameSync(directory, path.join(parent, "new-authority"));
    fs.renameSync(anchorDirectory, path.join(parent, "new-anchor"));
    fs.renameSync(oldAuthority, directory);
    fs.renameSync(oldAnchor, anchorDirectory);
    const restarted = createFileRevocationHandoff({ directory,
      anchor: createFileAuthorityAnchor({ directory: anchorDirectory }) });
    assert.equal((await restarted.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } })).status, "returned");
    assert.equal(callbacks, 2); // A shared rollback domain defeats the checkpoint.
  }));

test("an anchor refusing a claim blocks callback and leaves grant unspent", () =>
  fixture(async ({ directory, anchor, host }) => {
    const grant = host.issue(input());
    const unavailable = { read: () => anchor.read(),
      compareAndSwap: (expected, next) => next.sequence === 2 ? false :
        anchor.compareAndSwap(expected, next) };
    const another = createFileRevocationHandoff({ directory, anchor: unavailable });
    let callbacks = 0;
    const blocked = await another.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } });
    assert.deepEqual([blocked.status, blocked.dispatch_count, callbacks, anchor.read().sequence],
      ["indeterminate", 0, 0, 1]);
    assert.equal(fs.readdirSync(path.join(directory, "claimed")).length, 0);
  }));

test("a committed external advance with failed local write strands the old checkpoint", () =>
  fixture(async ({ directory, anchor, host }) => {
    const grant = host.issue(input());
    const interrupted = { read: () => anchor.read(),
      compareAndSwap(expected, next) {
        anchor.compareAndSwap(expected, next);
        if (next.sequence === 2) throw Error("lost local write");
        return true;
      } };
    const another = createFileRevocationHandoff({ directory, anchor: interrupted });
    let callbacks = 0;
    const result = await another.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { callbacks++; } });
    assert.equal(result.status, "indeterminate");
    assert.equal(callbacks, 0);
    assert.equal(anchor.read().sequence, 2);
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, "checkpoint.json"))).sequence, 1);
    assert.throws(() => createFileRevocationHandoff({ directory, anchor }),
      /authority_anchor_mismatch/);
  }));

test("an existing unanchored store cannot acquire a synthetic past, or host its anchor inside", () =>
  fixture(async ({ directory, anchor, host }) => {
    assert.throws(() => createFileRevocationHandoff({ directory, anchor,
      epochAnchor: { claimOnce() {}, advanceEpoch() {} } }),
    /incompatible anchor options/);
    assert.throws(() => createFileRevocationHandoff({ directory, anchor:
      createFileAuthorityAnchor({ directory: path.join(directory, "nested-anchor") }) }),
    /independent_anchor_directory_required/);
    const other = path.join(path.dirname(directory), "legacy");
    const legacy = createFileRevocationHandoff({ directory: other });
    legacy.issue(input());
    assert.throws(() => createFileRevocationHandoff({ directory: other, anchor }),
      /anchor_requires_empty_authority/);
    assert.equal(host.observeIssuer(input()).epoch, 0);
  }));
