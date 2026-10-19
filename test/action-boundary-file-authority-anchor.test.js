import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
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
async function fixture(run, { withClaim = false } = {}) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "aml-anchor-test-"));
  const directory = path.join(parent, "authority");
  const anchorDirectory = path.join(parent, "independent-anchor");
  const claimDirectory = path.join(parent, "independent-claims");
  try {
    const anchor = createFileAuthorityAnchor({ directory: anchorDirectory });
    if (withClaim) fs.mkdirSync(claimDirectory, { mode: 0o700 });
    const host = createFileRevocationHandoff({ directory, anchor,
      ...(withClaim ? { claimOnce: createTestingClaimOnce(claimDirectory) } : {}) });
    return await run({ parent, directory, anchorDirectory, claimDirectory, anchor, host });
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
}

test("an independent checkpoint advances for issue, claim, and revocation", () =>
  fixture(async ({ directory, anchor, host }) => {
    assert.equal(anchor.read().sequence, 0);
    assert.equal(anchor.read().protocol, "aml-file-authority-checkpoint/2");
    assert.match(anchor.read().state_sha256, /^[0-9a-f]{64}$/);
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

test("checkpoint authority rejects a different claim mode and a lost mode record", () =>
  fixture(async ({ parent, directory, anchor, host }) => {
    const claimDirectory = path.join(parent, "additional-claims");
    fs.mkdirSync(claimDirectory, { mode: 0o700 });
    assert.throws(() => createFileRevocationHandoff({ directory, anchor,
      claimOnce: createTestingClaimOnce(claimDirectory) }), /authority_mode_mismatch/);
    const grant = host.issue(input());
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory,
      "authority-mode.json"), "utf8")).mode, "checkpoint-anchored");
    fs.rmSync(path.join(directory, "authority-mode.json"));
    assert.throws(() => host.issue(input()), /authority_mode_unavailable/);
    assert.throws(() => createFileRevocationHandoff({ directory, anchor }),
      /authority_mode_unavailable/);
    let calls = 0;
    const result = await host.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([result.status, result.dispatch_count, calls], ["indeterminate", 0, 0]);
    assert.equal(anchor.read().sequence, 1);
  }));

test("selectively restoring an epoch file cannot revive an unspent grant", () =>
  fixture(async ({ directory, anchorDirectory, anchor, host }) => {
    const grant = host.issue(input(), { operationId: "host-intent-selective-epoch" });
    assert.equal(host.revokeIssuer(input()).epoch, 1);
    const epochFile = path.join(directory, "epochs", fs.readdirSync(path.join(directory, "epochs"))[0]);
    fs.rmSync(epochFile); // Restore only the pre-revocation epoch (zero).
    assert.equal(anchor.read().sequence, 2); // Both checkpoint copies still agree.
    assert.throws(() => createFileRevocationHandoff({ directory, anchor }),
      /authority_state_mismatch/);
    const child = JSON.parse((await exec(process.execPath,
      [worker, directory, anchorDirectory, grant.grant_id])).stdout);
    assert.deepEqual([child.reason, child.dispatch_count], ["authority_state_mismatch", 0]);
    assert.equal(fs.existsSync(path.join(anchorDirectory, "effects.log")), false);
  }));

test("selectively deleting a spent marker cannot replay its callback", () =>
  fixture(async ({ directory, anchorDirectory, anchor, host }) => {
    const grant = host.issue(input());
    const first = JSON.parse((await exec(process.execPath,
      [worker, directory, anchorDirectory, grant.grant_id])).stdout);
    assert.equal(first.dispatch_count, 1);
    fs.rmSync(path.join(directory, "claimed", `${grant.grant_id}.json`));
    assert.equal(anchor.read().sequence, 2);
    const second = JSON.parse((await exec(process.execPath,
      [worker, directory, anchorDirectory, grant.grant_id])).stdout);
    assert.deepEqual([second.reason, second.dispatch_count], ["authority_state_mismatch", 0]);
    assert.equal(fs.readFileSync(path.join(anchorDirectory, "effects.log"), "utf8"), "callback\n");
  }));

test("selective grant edits and operation loss disagree with the checkpoint", () =>
  fixture(async ({ directory, anchor, host }) => {
    const grant = host.issue(input(), { operationId: "host-intent-selective-grant" });
    const grantFile = path.join(directory, "grants", `${grant.grant_id}.json`);
    const original = fs.readFileSync(grantFile);
    const changed = JSON.parse(original);
    changed.expires_at_ms++;
    fs.writeFileSync(grantFile, JSON.stringify(changed) + "\n");
    assert.throws(() => createFileRevocationHandoff({ directory, anchor }),
      /authority_state_mismatch/);
    fs.writeFileSync(grantFile, original);
    assert.equal(createFileRevocationHandoff({ directory, anchor }).observeIssuer(input()).epoch, 0);
    const operationFile = path.join(directory, "operations",
      fs.readdirSync(path.join(directory, "operations"))[0]);
    fs.rmSync(operationFile);
    assert.throws(() => createFileRevocationHandoff({ directory, anchor }),
      /authority_state_mismatch/);
  }));

test("a protocol-1 checkpoint with a mode pin remains readable without an upgrade", () =>
  fixture(async ({ parent }) => {
    const directory = path.join(parent, "legacy-authority");
    const anchor = createFileAuthorityAnchor({ directory: path.join(parent, "legacy-anchor") });
    createFileRevocationHandoff({ directory }); // Create an otherwise empty authority.
    fs.writeFileSync(path.join(directory, "authority-mode.json"), JSON.stringify({
      protocol: "aml-file-authority-mode/1", mode: "checkpoint-anchored"
    }) + "\n", { mode: 0o600 });
    const initial = { protocol: "aml-file-authority-checkpoint/1", store_id: randomUUID(),
      sequence: 0, head_sha256: "a".repeat(64) };
    assert.equal(anchor.compareAndSwap(null, initial), true);
    fs.writeFileSync(path.join(directory, "checkpoint.json"), JSON.stringify(initial) + "\n",
      { mode: 0o600 });
    const legacy = createFileRevocationHandoff({ directory, anchor });
    const grant = legacy.issue(input());
    assert.equal((await legacy.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => true })).status, "returned");
    assert.equal(anchor.read().protocol, "aml-file-authority-checkpoint/1");
    assert.equal(Object.hasOwn(anchor.read(), "state_sha256"), false);
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
  fixture(async ({ directory, anchor, claimDirectory, host }) => {
    const claim = createTestingClaimOnce(claimDirectory);
    const grant = host.issue(input(), { operationId: "host-intent-two-anchors" });
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory,
      "authority-mode.json"), "utf8")).mode, "checkpoint-claim-anchored");
    const combined = createFileRevocationHandoff({ directory, anchor, claimOnce: claim });
    let calls = 0;
    const first = await combined.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { calls++; return true; } });
    const retry = await combined.dispatch({ ...input(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([first.status, retry.dispatch_count, calls, anchor.read().sequence],
      ["returned", 0, 1, 2]);
    assert.equal(fs.readdirSync(claimDirectory).length, 1);
  }, { withClaim: true }));

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
  }, { withClaim: true }));

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
      /authority_mode_mismatch/);
    assert.equal(host.observeIssuer(input()).epoch, 0);
  }));
