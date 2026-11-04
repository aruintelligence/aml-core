import test from "node:test";
import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createFileOneShotGrants } from "../pilots/action-boundary/file-one-shot-grants.mjs";
import { runFileGrantRace } from "../pilots/action-boundary/file-grant-race-demo.mjs";
import { dispatchAction, planAction } from "../pilots/action-boundary/boundary.mjs";

const digest = "a".repeat(64);

async function withDirectory(run) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "aml-grant-test-"));
  try { return await run(directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

test("two separate Node processes claim one grant and invoke only one callback", async () => {
  const report = await runFileGrantRace();
  const published = JSON.parse(await readFile(new URL("../docs/approval-race-report.json", import.meta.url)));
  assert.deepEqual(report, published);
  assert.equal(report.total_tool_callbacks, 1);
  assert.equal(report.claim_markers, 1);
  assert.deepEqual(report.outcomes.map(row => [row.status, row.tool_calls]),
    [["blocked", 0], ["dispatched", 1]]);
});

test("a claim persists across store instances and rejects reuse", () => withDirectory(async directory => {
  const first = createFileOneShotGrants({ directory });
  const grant = await first.issue(digest);
  const second = createFileOneShotGrants({ directory });
  assert.equal(await second.consume({ approval: grant, proposal_sha256: digest }), true);
  assert.equal(await first.consume({ approval: grant, proposal_sha256: digest }), false);
  assert.equal((await readdir(path.join(directory, "claimed"))).length, 1);
}));

test("a worker dying after claim cannot replay the grant after restart", () =>
  withDirectory(async directory => {
    const store = createFileOneShotGrants({ directory });
    const grant = await store.issue(digest);
    const worker = new URL("../pilots/action-boundary/file-grant-crash-worker.mjs", import.meta.url);
    const exitCode = await new Promise((resolve, reject) => {
      const child = fork(worker, [directory, JSON.stringify(grant), digest],
        { stdio: ["ignore", "ignore", "ignore", "ipc"] });
      child.once("error", reject);
      child.once("exit", resolve);
    });
    assert.equal(exitCode, 86);
    const restarted = createFileOneShotGrants({ directory });
    assert.equal(await restarted.consume({ approval: grant, proposal_sha256: digest }), false);
    assert.equal((await readdir(path.join(directory, "claimed"))).length, 1);
  }));

test("losing the spent-marker directory cannot be repaired by issuing a new grant", () =>
  withDirectory(async directory => {
    const store = createFileOneShotGrants({ directory });
    const grant = await store.issue(digest);
    assert.equal(await store.consume({ approval: grant, proposal_sha256: digest }), true);
    await rm(path.join(directory, "claimed"), { recursive: true });
    await assert.rejects(() => store.issue("b".repeat(64)));
    await assert.rejects(() => createFileOneShotGrants({ directory }).issue("b".repeat(64)));
    await assert.rejects(() => store.consume({ approval: grant, proposal_sha256: digest }));
    assert.equal((await readdir(directory)).includes("claimed"), false);
  }));

test("a missing or damaged store marker cannot silently initialize over old grants", () =>
  withDirectory(async directory => {
    const store = createFileOneShotGrants({ directory });
    await store.issue(digest);
    await rm(path.join(directory, "store-state.json"));
    await assert.rejects(() => createFileOneShotGrants({ directory }).issue(digest),
      /grant_store_incomplete/);
    assert.deepEqual(await readdir(path.join(directory, "claimed")), []);
  }));

test("expiry, digest mismatch, and invalid IDs fail without creating a claim", () => withDirectory(async directory => {
  let clock = 1000;
  const store = createFileOneShotGrants({ directory, now: () => clock });
  const grant = await store.issue(digest, { ttlMs: 100 });
  assert.equal(await store.consume({ approval: { ...grant, approval_id: "../escape" },
    proposal_sha256: digest }), false);
  assert.equal(await store.consume({ approval: grant, proposal_sha256: "b".repeat(64) }), false);
  clock = 1100;
  assert.equal(await store.consume({ approval: grant, proposal_sha256: digest }), false);
  assert.deepEqual(await readdir(path.join(directory, "claimed")), []);
}));

test("a claim-store error blocks dispatch rather than calling the tool", () => withDirectory(async directory => {
  const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
    resource: "team@example.test", purpose: "Send a status update", arguments: { body: "Hi" } };
  const policy = { protocol: "aml-action-policy/1", rules: [
    { tool: "send_message", effect: "send", resource: "team@example.test", requires_approval: true }
  ] };
  const store = createFileOneShotGrants({ directory });
  const grant = await store.issue(planAction(proposal, policy).proposal_sha256);
  await rm(path.join(directory, "claimed"), { recursive: true });
  await writeFile(path.join(directory, "claimed"), "not a directory");
  let calls = 0;
  const outcome = await dispatchAction(proposal, { policy, requestApproval: async () => grant,
    consumeApproval: store.consume, executeTool: async () => { calls++; } });
  assert.equal(outcome.receipt.reason, "approval_consume_error");
  assert.equal(outcome.receipt.execution_status, "blocked");
  assert.equal(calls, 0);
}));

test("a torn issued-grant record blocks dispatch without a callback", () => withDirectory(async directory => {
  const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
    resource: "team@example.test", purpose: "Test corrupt grant", arguments: { body: "Hi" } };
  const policy = { protocol: "aml-action-policy/1", rules: [
    { tool: proposal.tool, effect: proposal.effect, resource: proposal.resource, requires_approval: true }
  ] };
  const store = createFileOneShotGrants({ directory });
  const grant = await store.issue(planAction(proposal, policy).proposal_sha256);
  await writeFile(path.join(directory, "issued", `${grant.approval_id}.json`), '{"approval_id":');
  let calls = 0;
  const outcome = await dispatchAction(proposal, { policy, requestApproval: async () => grant,
    consumeApproval: store.consume, executeTool: async () => { calls++; } });
  assert.equal(outcome.receipt.execution_status, "blocked");
  assert.equal(outcome.receipt.reason, "approval_consume_error");
  assert.equal(calls, 0);
  assert.deepEqual(await readdir(path.join(directory, "claimed")), []);
}));

test("a pre-existing writable root or claim directory cannot issue a grant", () =>
  withDirectory(async directory => {
    const store = createFileOneShotGrants({ directory });
    await chmod(directory, 0o777);
    await assert.rejects(() => store.issue(digest), /private_grant_directory_required/);
    assert.deepEqual(await readdir(directory), []);
    await chmod(directory, 0o700);
    await mkdir(path.join(directory, "claimed"), { mode: 0o777 });
    await assert.rejects(() => store.issue(digest), /grant_store_incomplete/);
    assert.deepEqual(await readdir(directory), ["claimed"]);
  }));

test("a claim directory made writable after issuance blocks before callback", () =>
  withDirectory(async directory => {
    const proposal = { protocol: "aml-proposed-action/1", tool: "send_message", effect: "send",
      resource: "team@example.test", purpose: "Test local store", arguments: { body: "Hello" } };
    const policy = { protocol: "aml-action-policy/1", rules: [
      { tool: proposal.tool, effect: proposal.effect, resource: proposal.resource, requires_approval: true }
    ] };
    const store = createFileOneShotGrants({ directory });
    const grant = await store.issue(planAction(proposal, policy).proposal_sha256);
    await chmod(path.join(directory, "claimed"), 0o777);
    let calls = 0;
    const outcome = await dispatchAction(proposal, { policy, requestApproval: async () => grant,
      consumeApproval: store.consume, executeTool: async () => { calls++; } });
    assert.equal(outcome.receipt.reason, "approval_consume_error");
    assert.equal(outcome.receipt.execution_status, "blocked");
    assert.equal(calls, 0);
    assert.deepEqual(await readdir(path.join(directory, "claimed")), []);
  }));

test("a symlinked claim directory is rejected instead of followed", () =>
  withDirectory(async directory => {
    const outside = path.join(directory, "outside");
    const root = path.join(directory, "private");
    await mkdir(outside, { mode: 0o700 });
    await mkdir(root, { mode: 0o700 });
    await symlink(outside, path.join(root, "claimed"));
    const store = createFileOneShotGrants({ directory: root });
    await assert.rejects(() => store.issue(digest), /grant_store_incomplete/);
    assert.deepEqual(await readdir(outside), []);
  }));
