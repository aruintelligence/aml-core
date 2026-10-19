import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createFileRevocationHandoff,
  inspectFileRevocationHandoff } from "../pilots/action-boundary/file-revocation-handoff.mjs";
import { createTestingClaimOnce } from "../pilots/action-boundary/testing-claim-anchor.mjs";
import { createTestingEpochAnchor } from "../pilots/action-boundary/testing-epoch-anchor.mjs";

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

test("one host operation cannot mint a second grant, but a new intent can", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    const first = host.issue(context(), { operationId: "host-intent-001" });
    assert.ok(first.grant_id);
    assert.throws(() => host.issue(context(), { operationId: "host-intent-001" }),
      /operation_already_claimed/);
    assert.throws(() => host.issue({ ...context(), preparedRequest: {
      ...context().preparedRequest, body: "changed"
    } }, { operationId: "host-intent-001" }), /operation_payload_mismatch/);
    const second = host.issue(context(), { operationId: "host-intent-002" });
    assert.notEqual(second.grant_id, first.grant_id);
    assert.equal(fs.readdirSync(path.join(directory, "operations")).length, 2);
    const anotherTenant = host.issue({ ...context(), tenant: "tenant-b" },
      { operationId: "host-intent-001" });
    assert.ok(anotherTenant.grant_id);
    assert.throws(() => host.issue(context(), { operationId: "host-intent-001 " }),
      /Invalid host operation ID/);
  }));

test("an operation marker survives a missing grant and suppresses a fresh instance", () =>
  withAsyncDirectory(async directory => {
    const original = createFileRevocationHandoff({ directory });
    const grant = original.issue(context(), { operationId: "host-intent-orphan-004" });
    fs.rmSync(path.join(directory, "grants", `${grant.grant_id}.json`));
    const restarted = createFileRevocationHandoff({ directory });
    assert.throws(() => restarted.issue(context(), { operationId: "host-intent-orphan-004" }),
      /operation_already_claimed/);
    let calls = 0;
    const outcome = await restarted.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([outcome.status, outcome.dispatch_count, calls], ["blocked", 0, 0]);
  }));

test("an unavailable operation record suppresses a grant before callback", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory });
    const grant = host.issue(context(), { operationId: "host-intent-003" });
    fs.rmSync(path.join(directory, "operations", fs.readdirSync(path.join(directory,
      "operations"))[0]));
    let calls = 0;
    const result = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([result.status, result.reason, result.dispatch_count, calls],
      ["indeterminate", "operation_record_unavailable", 0, 0]);
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
    const report = inspectFileRevocationHandoff({ directory });
    assert.equal(report.lock, "present");
    assert.equal(report.reconciliation.candidates[0].grant_id, grant.grant_id);
    assert.equal(report.reconciliation.candidates[0].local_outcome, "missing");
    assert.ok(report.reasons.includes("claims_need_provider_review"));
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
    for (const child of ["epochs", "grants", "operations", "claimed", "outcomes"]) {
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

test("a separately held atomic claim blocks replay after store rollback and process restart", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchor = path.join(parent, "held-claims");
    fs.mkdirSync(anchor, { mode: 0o700 });
    const host = createFileRevocationHandoff({ directory,
      claimOnce: createTestingClaimOnce(anchor) });
    const grant = host.issue(context());
    const snapshot = path.join(parent, "snapshot");
    fs.cpSync(directory, snapshot, { recursive: true });
    fs.chmodSync(snapshot, 0o700);
    for (const child of ["epochs", "grants", "operations", "claimed", "outcomes"]) {
      fs.chmodSync(path.join(snapshot, child), 0o700);
    }
    fs.chmodSync(path.join(snapshot, "clock.json"), 0o600);
    fs.chmodSync(path.join(snapshot, "grants", `${grant.grant_id}.json`), 0o600);
    let calls = 0;
    const first = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; return "sent"; } });
    assert.equal(first.status, "returned");
    assert.equal(fs.readdirSync(anchor).length, 1);
    fs.renameSync(directory, path.join(parent, "spent"));
    fs.renameSync(snapshot, directory);

    const restarted = await exec(process.execPath,
      [worker, directory, grant.grant_id, "anchored", anchor]);
    const result = JSON.parse(restarted.stdout);
    assert.deepEqual([result.status, result.reason, result.dispatch_count],
      ["blocked", "external_claim_spent", 0]);
    assert.equal(calls, 1);
    assert.equal(fs.existsSync(path.join(directory, "effects.log")), false);
    fs.rmSync(path.join(parent, "spent"), { recursive: true, force: true });
  }));

test("a host operation claim survives rollback and a newly minted grant", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchor = path.join(parent, "held-claims");
    fs.mkdirSync(anchor, { mode: 0o700 });
    const firstHost = createFileRevocationHandoff({ directory,
      claimOnce: createTestingClaimOnce(anchor) });
    const snapshot = path.join(parent, "snapshot");
    fs.cpSync(directory, snapshot, { recursive: true });
    fs.chmodSync(snapshot, 0o700);
    for (const child of ["epochs", "grants", "operations", "claimed", "outcomes"]) {
      fs.chmodSync(path.join(snapshot, child), 0o700);
    }
    const firstGrant = firstHost.issue(context(), { operationId: "host-intent-rollback-001" });
    let calls = 0;
    const first = await firstHost.dispatch({ ...context(), grant_id: firstGrant.grant_id,
      execute: () => { calls++; return "sent"; } });
    assert.equal(first.status, "returned");
    fs.renameSync(directory, path.join(parent, "spent"));
    fs.renameSync(snapshot, directory);

    const restarted = createFileRevocationHandoff({ directory,
      claimOnce: createTestingClaimOnce(anchor) });
    const newGrant = restarted.issue(context(), { operationId: "host-intent-rollback-001" });
    assert.notEqual(newGrant.grant_id, firstGrant.grant_id);
    const replay = await restarted.dispatch({ ...context(), grant_id: newGrant.grant_id,
      execute: () => { calls++; return "replayed"; } });
    assert.deepEqual([replay.status, replay.reason, replay.dispatch_count, calls],
      ["blocked", "external_claim_spent", 0, 1]);
    assert.equal(fs.readdirSync(anchor).length, 1);
    fs.rmSync(path.join(parent, "spent"), { recursive: true, force: true });
  }));

test("an external issuer epoch rejects unspent grants after local rollback and restart", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchorDirectory = path.join(parent, "epoch-anchor");
    fs.mkdirSync(anchorDirectory, { mode: 0o700 });
    const host = createFileRevocationHandoff({ directory,
      epochAnchor: createTestingEpochAnchor(anchorDirectory) });
    const grant = host.issue(context());
    const snapshot = path.join(parent, "before-revocation");
    fs.cpSync(directory, snapshot, { recursive: true });
    fs.chmodSync(snapshot, 0o700);
    for (const child of ["epochs", "grants", "operations", "claimed", "outcomes"]) {
      fs.chmodSync(path.join(snapshot, child), 0o700);
    }
    fs.chmodSync(path.join(snapshot, "clock.json"), 0o600);
    fs.chmodSync(path.join(snapshot, "grants", `${grant.grant_id}.json`), 0o600);

    assert.throws(() => host.revokeIssuer(context()), /anchored_revocation_required/);
    assert.equal((await host.revokeIssuerAnchored(context())).epoch, 1);
    fs.renameSync(directory, path.join(parent, "revoked-local"));
    fs.renameSync(snapshot, directory);

    const downgraded = await exec(process.execPath,
      [worker, directory, grant.grant_id, "normal"]);
    assert.deepEqual([JSON.parse(downgraded.stdout).reason,
      JSON.parse(downgraded.stdout).dispatch_count], ["authority_mode_mismatch", 0]);
    const restarted = await exec(process.execPath,
      [worker, directory, grant.grant_id, "epoch-anchored", anchorDirectory]);
    const result = JSON.parse(restarted.stdout);
    assert.deepEqual([result.status, result.reason, result.dispatch_count],
      ["blocked", "external_claim_or_epoch_rejected", 0]);
    assert.equal(fs.existsSync(path.join(directory, "effects.log")), false);
    const afterRollback = createFileRevocationHandoff({ directory,
      epochAnchor: createTestingEpochAnchor(anchorDirectory) });
    const newGrant = afterRollback.issue(context());
    let calls = 0;
    const stale = await afterRollback.dispatch({ ...context(), grant_id: newGrant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([stale.status, stale.reason, calls],
      ["blocked", "external_claim_or_epoch_rejected", 0]);
    await assert.rejects(afterRollback.revokeIssuerAnchored(context()), /external_epoch_mismatch/);
    assert.equal(fs.existsSync(path.join(directory, "authority.lock")), true);
    fs.rmSync(path.join(parent, "revoked-local"), { recursive: true, force: true });
  }));

test("an epoch anchor requires both atomic operations and excludes the spent-only hook", () =>
  withAsyncDirectory(async directory => {
    assert.throws(() => createFileRevocationHandoff({ directory,
      epochAnchor: { claimOnce: () => true } }), /optional atomic host anchor/);
    assert.throws(() => createFileRevocationHandoff({ directory,
      epochAnchor: { claimOnce: () => true, advanceEpoch: () => true },
      claimOnce: () => true }), /optional atomic host anchor/);
  }));

test("an epoch-aware claim dispatches once in each current issuer epoch", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchorDirectory = path.join(parent, "epoch-anchor");
    fs.mkdirSync(anchorDirectory, { mode: 0o700 });
    const fixture = createTestingEpochAnchor(anchorDirectory);
    const seenEpochs = [];
    const host = createFileRevocationHandoff({ directory, epochAnchor: {
      advanceEpoch: record => {
        assert.equal(Object.isFrozen(record), true);
        return fixture.advanceEpoch(record);
      },
      claimOnce: record => {
        assert.equal(Object.isFrozen(record), true);
        assert.equal(record.protocol, "aml-file-authority-external-claim/2");
        seenEpochs.push(record.epoch);
        return fixture.claimOnce(record);
      }
    } });
    let calls = 0;
    const first = host.issue(context(), { operationId: "host-intent-epoch-0" });
    assert.equal((await host.dispatch({ ...context(), grant_id: first.grant_id,
      execute: () => { calls++; return "sent"; } })).status, "returned");
    assert.equal((await host.revokeIssuerAnchored(context())).epoch, 1);
    const second = host.issue(context(), { operationId: "host-intent-epoch-1" });
    assert.equal((await host.dispatch({ ...context(), grant_id: second.grant_id,
      execute: () => { calls++; return "sent"; } })).status, "returned");
    assert.deepEqual([seenEpochs, calls], [[0, 1], 2]);
  }));

test("a grant issued with an epoch anchor rejects downgraded workers", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchorDirectory = path.join(parent, "epoch-anchor");
    fs.mkdirSync(anchorDirectory, { mode: 0o700 });
    const host = createFileRevocationHandoff({ directory,
      epochAnchor: createTestingEpochAnchor(anchorDirectory) });
    const grant = host.issue(context());
    const saved = JSON.parse(fs.readFileSync(path.join(directory, "grants",
      `${grant.grant_id}.json`), "utf8"));
    assert.equal(saved.required_claim_protocol, "aml-file-authority-external-claim/2");
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory,
      "authority-mode.json"), "utf8")).mode, "epoch-anchored");
    assert.throws(() => createFileRevocationHandoff({ directory }).issue(context()),
      /authority_mode_mismatch/);
    assert.throws(() => createFileRevocationHandoff({ directory }).revokeIssuer(context()),
      /authority_mode_mismatch/);
    for (const mode of ["normal", "anchored"]) {
      const attempted = await exec(process.execPath,
        [worker, directory, grant.grant_id, mode, anchorDirectory]);
      const result = JSON.parse(attempted.stdout);
      assert.deepEqual([result.status, result.reason, result.dispatch_count],
        ["indeterminate", "authority_mode_mismatch", 0]);
    }
    assert.equal(fs.existsSync(path.join(directory, "effects.log")), false);
    assert.equal(fs.readdirSync(path.join(directory, "claimed")).length, 0);
    const correct = await exec(process.execPath,
      [worker, directory, grant.grant_id, "epoch-anchored", anchorDirectory]);
    assert.equal(JSON.parse(correct.stdout).dispatch_count, 1);
    assert.equal(fs.readFileSync(path.join(directory, "effects.log"), "utf8"), "callback\n");
  }));

test("a spent-only anchored grant rejects an unanchored worker and invalid mode data", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchorDirectory = path.join(parent, "held-claims");
    fs.mkdirSync(anchorDirectory, { mode: 0o700 });
    const host = createFileRevocationHandoff({ directory,
      claimOnce: createTestingClaimOnce(anchorDirectory) });
    const grant = host.issue(context());
    const unanchored = await exec(process.execPath,
      [worker, directory, grant.grant_id, "normal"]);
    assert.deepEqual([JSON.parse(unanchored.stdout).reason,
      JSON.parse(unanchored.stdout).dispatch_count], ["authority_mode_mismatch", 0]);
    const file = path.join(directory, "grants", `${grant.grant_id}.json`);
    const saved = JSON.parse(fs.readFileSync(file, "utf8"));
    fs.writeFileSync(file, JSON.stringify({ ...saved, required_claim_protocol: "unknown" }) + "\n");
    let calls = 0;
    const invalid = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([invalid.status, invalid.reason, invalid.dispatch_count, calls],
      ["indeterminate", "invalid_grant_record", 0, 0]);
  }));

test("a missing mode closes an existing store, and a grant retains its anchor requirement", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchorDirectory = path.join(parent, "epoch-anchor");
    fs.mkdirSync(anchorDirectory, { mode: 0o700 });
    const host = createFileRevocationHandoff({ directory,
      epochAnchor: createTestingEpochAnchor(anchorDirectory) });
    const grant = host.issue(context());
    const copy = path.join(parent, "copy-without-mode");
    fs.cpSync(directory, copy, { recursive: true });
    fs.chmodSync(copy, 0o700);
    for (const child of ["epochs", "grants", "operations", "claimed", "outcomes"]) {
      fs.chmodSync(path.join(copy, child), 0o700);
    }
    fs.chmodSync(path.join(copy, "clock.json"), 0o600);
    fs.chmodSync(path.join(copy, "grants", `${grant.grant_id}.json`), 0o600);
    fs.rmSync(path.join(copy, "authority-mode.json"));
    const downgraded = await exec(process.execPath,
      [worker, copy, grant.grant_id, "normal"]);
    assert.deepEqual([JSON.parse(downgraded.stdout).reason,
      JSON.parse(downgraded.stdout).dispatch_count], ["authority_store_unavailable", 0]);
    assert.throws(() => createFileRevocationHandoff({ directory: copy }).issue(context()),
      /authority_mode_unavailable/);
    assert.equal(fs.existsSync(path.join(copy, "effects.log")), false);
    assert.equal(fs.readdirSync(path.join(copy, "claimed")).length, 0);

    // The grant still guards dispatch if the local mode is replaced with a
    // syntactically valid weaker mode. The local record is not tamper proof.
    const weaker = path.join(parent, "copy-with-weaker-mode");
    fs.cpSync(directory, weaker, { recursive: true });
    fs.chmodSync(weaker, 0o700);
    for (const child of ["epochs", "grants", "operations", "claimed", "outcomes"]) {
      fs.chmodSync(path.join(weaker, child), 0o700);
    }
    fs.chmodSync(path.join(weaker, "clock.json"), 0o600);
    fs.chmodSync(path.join(weaker, "grants", `${grant.grant_id}.json`), 0o600);
    fs.writeFileSync(path.join(weaker, "authority-mode.json"), JSON.stringify({
      protocol: "aml-file-authority-mode/1", mode: "local"
    }) + "\n", { mode: 0o600 });
    const pinned = await exec(process.execPath,
      [worker, weaker, grant.grant_id, "normal"]);
    assert.deepEqual([JSON.parse(pinned.stdout).reason,
      JSON.parse(pinned.stdout).dispatch_count], ["required_anchor_unavailable", 0]);
    assert.equal(fs.existsSync(path.join(weaker, "effects.log")), false);
    assert.equal(fs.readdirSync(path.join(weaker, "claimed")).length, 0);
  }));

test("an uncertain external epoch advance strands the local lock", () =>
  withAsyncDirectory(async directory => {
    const host = createFileRevocationHandoff({ directory, epochAnchor: {
      claimOnce: () => true,
      advanceEpoch: async () => { throw Error("external service unavailable"); }
    } });
    const grant = host.issue(context());
    await assert.rejects(host.revokeIssuerAnchored(context()), /external_epoch_unavailable/);
    assert.equal(fs.existsSync(path.join(directory, "authority.lock")), true);
    let calls = 0;
    const result = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([result.status, result.reason, result.dispatch_count, calls],
      ["indeterminate", "authority_busy_or_crashed", 0, 0]);
  }));

test("a committed external epoch with a lost response still rejects restored grants", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchorDirectory = path.join(parent, "epoch-anchor");
    fs.mkdirSync(anchorDirectory, { mode: 0o700 });
    const fixture = createTestingEpochAnchor(anchorDirectory);
    const host = createFileRevocationHandoff({ directory, epochAnchor: {
      claimOnce: record => fixture.claimOnce(record),
      advanceEpoch: record => {
        assert.equal(fixture.advanceEpoch(record), true);
        throw Error("reply lost after commit");
      }
    } });
    const grant = host.issue(context());
    const snapshot = path.join(parent, "before-revocation");
    fs.cpSync(directory, snapshot, { recursive: true });
    fs.chmodSync(snapshot, 0o700);
    for (const child of ["epochs", "grants", "operations", "claimed", "outcomes"]) {
      fs.chmodSync(path.join(snapshot, child), 0o700);
    }
    fs.chmodSync(path.join(snapshot, "clock.json"), 0o600);
    fs.chmodSync(path.join(snapshot, "grants", `${grant.grant_id}.json`), 0o600);
    await assert.rejects(host.revokeIssuerAnchored(context()), /external_epoch_unavailable/);
    assert.equal(fs.existsSync(path.join(directory, "authority.lock")), true);
    fs.renameSync(directory, path.join(parent, "stranded"));
    fs.renameSync(snapshot, directory);

    const restarted = await exec(process.execPath,
      [worker, directory, grant.grant_id, "epoch-anchored", anchorDirectory]);
    const result = JSON.parse(restarted.stdout);
    assert.deepEqual([result.status, result.reason, result.dispatch_count],
      ["blocked", "external_claim_or_epoch_rejected", 0]);
    assert.equal(fs.existsSync(path.join(directory, "effects.log")), false);
    fs.rmSync(path.join(parent, "stranded"), { recursive: true, force: true });
  }));

test("an awaited external revocation blocks local dispatch until its epoch is durable", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    const anchorDirectory = path.join(parent, "epoch-anchor");
    fs.mkdirSync(anchorDirectory, { mode: 0o700 });
    const fixture = createTestingEpochAnchor(anchorDirectory);
    let continueAdvance, entered;
    const pending = new Promise(resolve => { continueAdvance = resolve; });
    const waiting = new Promise(resolve => { entered = resolve; });
    const host = createFileRevocationHandoff({ directory, epochAnchor: {
      claimOnce: record => fixture.claimOnce(record),
      advanceEpoch: async record => { entered(); await pending; return fixture.advanceEpoch(record); }
    } });
    const grant = host.issue(context());
    const revocation = host.revokeIssuerAnchored(context());
    await waiting;
    let calls = 0;
    const busy = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([busy.reason, busy.dispatch_count, calls], ["authority_busy_or_crashed", 0, 0]);
    continueAdvance();
    assert.equal((await revocation).epoch, 1);
    const blocked = await host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    assert.deepEqual([blocked.reason, blocked.dispatch_count, calls], ["issuer_revoked", 0, 0]);
  }));

test("an uncertain or rejected external claim spends locally and never calls the provider", () =>
  withAsyncDirectory(async parent => {
    let calls = 0;
    const outcomes = [
      [() => false, "blocked", "external_claim_spent"],
      [() => { throw Error("anchor offline"); }, "indeterminate", "external_claim_unavailable"],
      [async () => { throw Error("anchor offline"); }, "indeterminate", "external_claim_unavailable"],
      [() => ({ accepted: true }), "indeterminate", "external_claim_unavailable"]
    ];
    for (const [claimOnce, status, reason] of outcomes) {
      const directory = fs.mkdtempSync(path.join(parent, "authority-"));
      const host = createFileRevocationHandoff({ directory, claimOnce });
      const grant = host.issue(context());
      const result = await host.dispatch({ ...context(), grant_id: grant.grant_id,
        execute: () => { calls++; } });
      assert.deepEqual([result.status, result.reason, result.dispatch_count], [status, reason, 0]);
      assert.equal(fs.existsSync(path.join(directory, "claimed", `${grant.grant_id}.json`)), true);
      const retry = await host.dispatch({ ...context(), grant_id: grant.grant_id,
        execute: () => { calls++; } });
      assert.equal(retry.reason, "grant_spent_or_uncertain");
    }
    assert.equal(calls, 0);
  }));

test("async external claim holds the local lock until the provider handoff", () =>
  withAsyncDirectory(async directory => {
    let allowClaim;
    const pending = new Promise(resolve => { allowClaim = resolve; });
    let entered;
    const waiting = new Promise(resolve => { entered = resolve; });
    let calls = 0;
    const host = createFileRevocationHandoff({ directory, claimOnce: async record => {
      assert.equal(Object.isFrozen(record), true);
      assert.match(record.claim_key_sha256, /^[0-9a-f]{64}$/);
      entered();
      return pending;
    } });
    const grant = host.issue(context());
    const action = host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; return "sent"; } });
    await waiting;
    assert.equal(calls, 0);
    assert.throws(() => createFileRevocationHandoff({ directory }).revokeIssuer({
      tenant: "tenant-a", issuer: "host-a"
    }), /authority_busy_or_crashed/);
    allowClaim(true);
    const result = await action;
    assert.deepEqual([result.status, result.dispatch_count, calls], ["returned", 1, 1]);
    assert.equal(createFileRevocationHandoff({ directory, claimOnce: () => true }).revokeIssuer({
      tenant: "tenant-a", issuer: "host-a"
    }).epoch, 1);
  }));

test("grant expiry during an awaited external claim blocks the provider callback", () =>
  withAsyncDirectory(async directory => {
    let time = 1_700_000_000_000;
    let resolveClaim;
    let entered;
    const waiting = new Promise(resolve => { entered = resolve; });
    const host = createFileRevocationHandoff({ directory, now: () => time,
      claimOnce: () => { entered(); return new Promise(resolve => { resolveClaim = resolve; }); } });
    const grant = host.issue(context(), { ttlMs: 10 });
    let calls = 0;
    const action = host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    await waiting;
    time += 10;
    resolveClaim(true);
    const result = await action;
    assert.deepEqual([result.status, result.reason, result.dispatch_count, calls],
      ["blocked", "grant_expired_or_clock_invalid", 0, 0]);
    assert.equal(fs.existsSync(path.join(directory, "claimed", `${grant.grant_id}.json`)), true);
  }));

test("a lost operation marker during an awaited claim blocks the callback", () =>
  withAsyncDirectory(async directory => {
    let resolveClaim;
    let entered;
    const waiting = new Promise(resolve => { entered = resolve; });
    const host = createFileRevocationHandoff({ directory,
      claimOnce: () => { entered(); return new Promise(resolve => { resolveClaim = resolve; }); } });
    const grant = host.issue(context(), { operationId: "host-intent-await-001" });
    let calls = 0;
    const action = host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    await waiting;
    fs.rmSync(path.join(directory, "operations", fs.readdirSync(path.join(directory,
      "operations"))[0]));
    resolveClaim(true);
    const result = await action;
    assert.deepEqual([result.status, result.reason, result.dispatch_count, calls],
      ["indeterminate", "operation_record_unavailable", 0, 0]);
  }));

test("a lost authority mode during an awaited claim blocks the callback", () =>
  withAsyncDirectory(async directory => {
    let resolveClaim, entered;
    const waiting = new Promise(resolve => { entered = resolve; });
    const host = createFileRevocationHandoff({ directory,
      claimOnce: () => { entered(); return new Promise(resolve => { resolveClaim = resolve; }); } });
    const grant = host.issue(context());
    let calls = 0;
    const action = host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    await waiting;
    fs.rmSync(path.join(directory, "authority-mode.json"));
    resolveClaim(true);
    const result = await action;
    assert.deepEqual([result.status, result.reason, result.dispatch_count, calls],
      ["indeterminate", "authority_store_unavailable", 0, 0]);
    assert.equal(fs.existsSync(path.join(directory, "claimed", `${grant.grant_id}.json`)), true);
  }));

test("an authority path replaced during an awaited claim cannot invoke the callback", () =>
  withAsyncDirectory(async parent => {
    const directory = path.join(parent, "authority");
    let resolveClaim;
    let entered;
    const waiting = new Promise(resolve => { entered = resolve; });
    const host = createFileRevocationHandoff({ directory,
      claimOnce: () => { entered(); return new Promise(resolve => { resolveClaim = resolve; }); } });
    const grant = host.issue(context());
    let calls = 0;
    const action = host.dispatch({ ...context(), grant_id: grant.grant_id,
      execute: () => { calls++; } });
    await waiting;
    fs.renameSync(directory, path.join(parent, "moved-authority"));
    fs.mkdirSync(directory, { mode: 0o700 });
    resolveClaim(true);
    const result = await action;
    assert.deepEqual([result.status, result.dispatch_count, calls], ["indeterminate", 0, 0]);
    assert.equal(fs.existsSync(path.join(parent, "moved-authority", "authority.lock")), true);
  }));
