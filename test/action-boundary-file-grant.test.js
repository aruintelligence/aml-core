import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
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
