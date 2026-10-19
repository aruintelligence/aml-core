import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createFileRevocationHandoff } from "../pilots/action-boundary/file-revocation-handoff.mjs";

const exec = promisify(execFile);
const worker = new URL("../pilots/action-boundary/file-revocation-worker.mjs", import.meta.url).pathname;
const context = () => ({
  tenant: "tenant-a", issuer: "host-a", actor: "reviewer-a", audience: "mail-service",
  tool: "send_mail", policy: { allowed: ["send_mail"], revision: 1 },
  preparedRequest: { to: ["team@example.test"], bcc: [], subject: "Update", body: "Approved" }
});
async function withAsyncDirectory(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-file-authority-"));
  try { return await run(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test("two separate processes race one grant and invoke at most one callback", () =>
  withAsyncDirectory(async directory => {
    const grant = createFileRevocationHandoff({ directory }).issue(context());
    const results = await Promise.all([0, 1].map(() => exec(process.execPath,
      [worker, directory, grant.grant_id])));
    const outcomes = results.map(row => JSON.parse(row.stdout));
    assert.equal(outcomes.filter(row => row.status === "returned").length, 1);
    assert.equal(outcomes.filter(row => row.dispatch_count === 0).length, 1);
    assert.equal(fs.readFileSync(path.join(directory, "effects.log"), "utf8"), "callback\n");
    const replay = await createFileRevocationHandoff({ directory }).dispatch({
      ...context(), grant_id: grant.grant_id, execute: () => { throw Error("must not run"); }
    });
    assert.equal(replay.reason, "grant_spent_or_uncertain");
  }));

test("revocation in a separate process blocks before callback", () =>
  withAsyncDirectory(async directory => {
    const first = createFileRevocationHandoff({ directory });
    const second = createFileRevocationHandoff({ directory });
    const grant = first.issue(context());
    const revoked = await exec(process.execPath, [worker, directory, grant.grant_id, "revoke"]);
    assert.equal(JSON.parse(revoked.stdout).epoch, 1);
    let calls = 0;
    const result = await first.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([result.status, result.reason, result.dispatch_count],
      ["blocked", "issuer_revoked", 0]);
    assert.equal(calls, 0);
    const next = second.issue(context());
    assert.equal((await first.dispatch({ ...context(), grant_id: next.grant_id,
      execute: () => { calls++; return true; } })).status, "returned");
    assert.equal(calls, 1);
  }));

test("conditional issuance rejects an epoch observed before cross-process revocation", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    const observed = host.observeIssuer(context());
    assert.deepEqual(observed, { epoch: 0 });
    await exec(process.execPath, [worker, directory, "unused", "revoke"]);
    assert.throws(() => host.issue(context(), { expectedEpoch: observed.epoch }), /issuer_revoked/);
    assert.equal(fs.readdirSync(path.join(directory, "grants")).length, 0);
    const next = host.observeIssuer(context());
    assert.deepEqual(next, { epoch: 1 });
    assert.ok(host.issue(context(), { expectedEpoch: next.epoch }).grant_id);
    assert.throws(() => host.issue(context(), { expectedEpoch: -1 }), /Invalid expected issuer epoch/);
  }));

test("one changed BCC, tenant, or policy cannot reuse the approved request", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    const input = context();
    const grant = host.issue(input);
    let calls = 0;
    for (const change of [
      { tenant: "tenant-b" },
      { policy: { allowed: ["send_mail"], revision: 2 } },
      { preparedRequest: { ...input.preparedRequest, bcc: ["other@example.test"] } }
    ]) {
      const result = await host.dispatch({ ...input, ...change, grant_id: grant.grant_id,
        execute: () => { calls++; } });
      assert.deepEqual([result.reason, result.dispatch_count], ["binding_mismatch", 0]);
    }
    assert.equal(calls, 0);
    assert.equal((await host.dispatch({ ...input, grant_id: grant.grant_id,
      execute: request => { calls++; assert.deepEqual(request, input.preparedRequest); } })).status, "returned");
    assert.equal(calls, 1);
  }));

test("ambiguous tenant or issuer spellings are rejected before namespace lookup", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    assert.throws(() => host.issue({ ...context(), tenant: "tenant-a " }), /Invalid tenant/);
    assert.throws(() => host.revokeIssuer({ tenant: "tenant-a", issuer: "host-a\n" }),
      /Invalid tenant or issuer/);
    const grant = host.issue(context());
    let calls = 0;
    const denied = await host.dispatch({ ...context(), tenant: "tenant-a ",
      grant_id: grant.grant_id, execute: () => { calls++; } });
    assert.deepEqual([denied.status, denied.dispatch_count], ["blocked", 0]);
    assert.equal(calls, 0);
  }));

test("persistent clock rejects expiry and rollback across processes; caller time is ignored", () =>
  withAsyncDirectory(async directory => {
    let time = 1000;
    const host = createFileRevocationHandoff({ directory, now: () => time });
    const grant = host.issue(context(), { ttlMs: 20 });
    time = 1020;
    let calls = 0;
    assert.equal((await host.dispatch({ ...context(), grant_id: grant.grant_id,
      now: 1001, execute: () => { calls++; } })).reason, "grant_expired_or_clock_invalid");
    const second = createFileRevocationHandoff({ directory, now: () => 900 });
    const result = await second.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([result.status, result.dispatch_count], ["indeterminate", 0]);
    assert.equal(calls, 0);
  }));

test("crash after claim strands the lock and cannot silently retry", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(context());
    await assert.rejects(() => exec(process.execPath, [worker, directory, grant.grant_id, "crash"]),
      error => error.code === 48);
    assert.equal(fs.readdirSync(path.join(directory, "claimed")).length, 1);
    let calls = 0;
    const result = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([result.status, result.reason, result.dispatch_count],
      ["indeterminate", "authority_busy_or_crashed", 0]);
    assert.throws(() => host.revokeIssuer({ tenant: "tenant-a", issuer: "host-a" }),
      /authority_busy_or_crashed/);
    assert.equal(calls, 0);
  }));

test("an uncertain epoch write or a writable claim directory fails closed", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(context());
    // A matching temp name must block this issuer's current epoch read.
    const entry = fs.readdirSync(path.join(directory, "grants"))[0];
    const key = JSON.parse(fs.readFileSync(path.join(directory, "grants", entry))).issuer_sha256;
    fs.writeFileSync(path.join(directory, "epochs", `${key}.json.uncertain.tmp`), "incomplete");
    let calls = 0;
    const uncertain = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.equal(uncertain.status, "indeterminate");
    fs.rmSync(path.join(directory, "epochs", `${key}.json.uncertain.tmp`));
    fs.chmodSync(path.join(directory, "claimed"), 0o777);
    const weak = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.equal(weak.status, "indeterminate");
    assert.equal(calls, 0);
  }));

test("provider rejection leaves a durable spent marker and an unknown outcome", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(context());
    let calls = 0;
    const first = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: async () => { calls++; throw Error("transport timeout"); } });
    assert.deepEqual([first.status, first.dispatch_count], ["outcome_unknown", 1]);
    const retry = await createFileRevocationHandoff({ directory }).dispatch({
      ...context(), grant_id: grant.grant_id, execute: () => { calls++; }
    });
    assert.deepEqual([retry.reason, retry.dispatch_count], ["grant_spent_or_uncertain", 0]);
    assert.equal(calls, 1);
  }));

test("corrupt clock record and a symlinked grant fail closed", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(context());
    let calls = 0;
    fs.writeFileSync(path.join(directory, "clock.json"), "null\n");
    const badClock = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.equal(badClock.status, "indeterminate");
    const grantFile = path.join(directory, "grants", `${grant.grant_id}.json`);
    const original = fs.readFileSync(grantFile);
    fs.rmSync(grantFile);
    fs.writeFileSync(path.join(directory, "held.json"), original, { mode: 0o600 });
    fs.symlinkSync(path.join(directory, "held.json"), grantFile);
    const badGrant = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.equal(badGrant.status, "indeterminate");
    assert.equal(calls, 0);
  }));

test("an ancestor symlink cannot switch the authority to an earlier grant snapshot", () =>
  withAsyncDirectory(async parent => {
    const actual = path.join(parent, "actual");
    fs.mkdirSync(actual, { mode: 0o700 });
    fs.symlinkSync(actual, path.join(parent, "alias"));
    assert.throws(() => createFileRevocationHandoff({
      directory: path.join(parent, "alias", "authority")
    }), /trusted_authority_path_required/);
  }));

test("a replaced private root cannot replay a spent grant in the same authority", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(context());
    const snapshot = path.join(parent, "snapshot");
    fs.cpSync(directory, snapshot, { recursive: true });
    fs.chmodSync(snapshot, 0o700);
    for (const child of ["epochs", "grants", "claimed", "outcomes"]) {
      fs.chmodSync(path.join(snapshot, child), 0o700);
    }
    fs.chmodSync(path.join(snapshot, "clock.json"), 0o600);
    fs.chmodSync(path.join(snapshot, "grants", `${grant.grant_id}.json`), 0o600);
    let calls = 0;
    const first = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; return "sent"; } });
    assert.equal(first.status, "returned");
    fs.renameSync(directory, path.join(parent, "spent"));
    fs.renameSync(snapshot, directory);
    const replay = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; return "sent again"; } });
    assert.deepEqual([replay.status, replay.dispatch_count], ["indeterminate", 0]);
    assert.equal(calls, 1);

    // The old inode pin is in memory. A fresh instance cannot distinguish a
    // host-restored old copy; deployments need an anchor outside this store.
    const restarted = createFileRevocationHandoff({ directory });
    const unanchored = await restarted.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; return "replayed after restart"; } });
    assert.equal(unanchored.status, "returned");
    assert.equal(calls, 2);
    fs.rmSync(path.join(parent, "spent"), { recursive: true, force: true });
  }));

test("a world-writable nonsticky parent cannot host the authority", () =>
  withAsyncDirectory(async parent => {
    fs.chmodSync(parent, 0o777);
    try {
      assert.throws(() => createFileRevocationHandoff({
        directory: path.join(parent, "authority")
      }), /trusted_authority_path_required/);
    } finally { fs.chmodSync(parent, 0o700); }
  }));
