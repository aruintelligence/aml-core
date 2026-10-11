import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createFileDispatchLedger } from "../pilots/action-boundary/file-dispatch-ledger.mjs";
import { runFileDispatchLedgerDemo } from "../pilots/action-boundary/file-dispatch-ledger-demo.mjs";
import { dispatchAction } from "../pilots/action-boundary/boundary.mjs";

const proposal = { protocol: "aml-proposed-action/1", tool: "simulated.send", effect: "send",
  resource: "mailbox:example", purpose: "test", arguments: { to: "example.invalid", body: "hello" } };
function fixture() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-ledger-test-"));
  const ledger = createFileDispatchLedger({ directory: path.join(temp, "private") });
  return { temp, ledger, done: () => fs.rmSync(temp, { recursive: true, force: true }) };
}

test("one host operation invokes one callback, and a distinct intent can reuse the proposal", async () => {
  const f = fixture();
  try {
    let calls = 0;
    const executeTool = () => { calls++; return { ok: true }; };
    const first = await f.ledger.run({ operationId: "host-operation-0001", proposal, executeTool });
    assert.equal(first.status, "returned");
    assert.deepEqual(first.result, { ok: true });
    const replay = await f.ledger.run({ operationId: "host-operation-0001", proposal, executeTool });
    assert.equal(replay.status, "already_returned");
    const changed = await f.ledger.run({ operationId: "host-operation-0001",
      proposal: { ...proposal, arguments: { ...proposal.arguments, body: "changed" } }, executeTool });
    assert.equal(changed.status, "mismatch");
    const newIntent = await f.ledger.run({ operationId: "host-operation-0002", proposal, executeTool });
    assert.equal(newIntent.status, "returned");
    assert.equal(calls, 2);
  } finally { f.done(); }
});

test("a claimed or thrown operation remains unknown across a new ledger instance", async () => {
  const f = fixture();
  try {
    assert.equal(f.ledger.claim({ operationId: "host-operation-0003", proposal }).status, "claimed");
    const recovered = createFileDispatchLedger({ directory: path.join(f.temp, "private") });
    let calls = 0;
    const failIfCalled = () => { calls++; };
    assert.equal((await recovered.run({ operationId: "host-operation-0003", proposal,
      executeTool: failIfCalled })).status, "unknown");
    const uncertain = await recovered.run({ operationId: "host-operation-0004", proposal,
      executeTool: () => { calls++; throw new Error("after side effect"); } });
    assert.equal(uncertain.status, "unknown");
    assert.equal((await recovered.run({ operationId: "host-operation-0004", proposal,
      executeTool: failIfCalled })).status, "unknown");
    assert.equal(calls, 1);
  } finally { f.done(); }
});

test("an incomplete marker, invalid host callback, and weak directory fail closed", async () => {
  const f = fixture();
  try {
    const id = "host-operation-0005";
    const file = path.join(f.temp, "private", crypto.createHash("sha256").update(id).digest("hex") + ".claim.json");
    fs.writeFileSync(file, "", { mode: 0o600 });
    let calls = 0;
    const result = await f.ledger.run({ operationId: id, proposal, executeTool: () => calls++ });
    assert.equal(result.status, "unknown");
    assert.equal(result.reason, "incomplete_claim");
    assert.equal(calls, 0);
    await assert.rejects(() => f.ledger.run({ operationId: "host-operation-0006", proposal }),
      /host_callback_required/);
    assert.equal(fs.readdirSync(path.join(f.temp, "private")).length, 1);
    const weak = path.join(f.temp, "wide");
    fs.mkdirSync(weak, { mode: 0o755 });
    assert.throws(() => createFileDispatchLedger({ directory: weak }), /private_directory_required/);
  } finally { f.done(); }
});

test("real child-process race and process exit produce the published six-scenario report", async () => {
  const report = await runFileDispatchLedgerDemo();
  assert.equal(report.scenarios.length, 6);
  assert.deepEqual(report.scenarios.map(row => row.callback_count), [1, 0, 0, 0, 1, 1]);
  assert.equal(report.scenarios[3].status, "unknown");
});

test("fresh approvals cannot replay the same host operation through the action boundary", async () => {
  const f = fixture();
  try {
    const policy = { protocol: "aml-action-policy/1", rules: [{ tool: proposal.tool,
      effect: proposal.effect, resource: proposal.resource, requires_approval: true }] };
    let callbacks = 0;
    const invoke = () => dispatchAction(proposal, { policy,
      requestApproval: async ({ proposal_sha256 }) => ({ approved: true, proposal_sha256 }),
      executeTool: async frozen => {
        const attempt = await f.ledger.run({ operationId: "host-operation-approved-001", proposal: frozen,
          executeTool: () => { callbacks++; return { simulated: true }; } });
        if (attempt.status !== "returned") throw new Error("No new dispatch was authorized");
        return attempt.result;
      } });
    assert.equal((await invoke()).receipt.execution_status, "dispatched");
    assert.equal((await invoke()).receipt.execution_status, "unknown");
    assert.equal(callbacks, 1);
  } finally { f.done(); }
});

test("claim digest and callback are bound to a single snapshot of a changing host object", async () => {
  const f = fixture();
  try {
    let reads = 0;
    const unusual = { ...proposal, arguments: { to: "example.invalid",
      get body() { return ++reads === 1 ? "first value" : "later value"; } } };
    let seen;
    const result = await f.ledger.run({ operationId: "host-operation-getter-001", proposal: unusual,
      executeTool: frozen => { seen = frozen.arguments.body;
        assert.throws(() => { frozen.arguments.body = "mutated"; }, TypeError); return true; } });
    assert.equal(reads, 1);
    assert.equal(seen, "first value");
    assert.equal(result.status, "returned");
    const staticFirst = { ...proposal, arguments: { to: "example.invalid", body: "first value" } };
    assert.equal(f.ledger.inspect({ operationId: "host-operation-getter-001", proposal: staticFirst }).status,
      "already_returned");
  } finally { f.done(); }
});
