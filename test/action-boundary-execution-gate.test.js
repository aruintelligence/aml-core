import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const provider = fileURLToPath(new URL("../pilots/action-boundary/sqlite-provider-fixture.py", import.meta.url));
const modules = path.dirname(provider);
function scenario(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-execution-gate-"));
  try {
    const providerDb = path.join(directory, "provider.sqlite");
    const gateDb = path.join(directory, "retained-gate.sqlite");
    const init = spawnSync("python3", ["-c",
      "import sys; sys.path.insert(0,sys.argv[1]); from sqlite_execution_gate import initialize; initialize(sys.argv[2])",
      modules, gateDb], { encoding: "utf8", timeout: 20_000 });
    assert.equal(init.status, 0, init.stderr);
    const operationId = crypto.randomUUID();
    const bytes = JSON.stringify({ operation_id: operationId,
      destination: "fixture:outbox", body: "approved" });
    const input = JSON.stringify({ request_bytes: bytes,
      request_sha256: crypto.createHash("sha256").update(bytes).digest("hex") });
    const send = (gate = gateDb, fault) => spawnSync("python3", [provider, providerDb, "request",
      ...(gate === null ? [] : [gate])], { input: fault ?
        JSON.stringify({ ...JSON.parse(input), fault }) : input,
      encoding: "utf8", timeout: 20_000 });
    const remove = database => {
      const r = spawnSync("python3", ["-c",
        "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DELETE FROM '+sys.argv[2]); c.commit()",
        database, database === gateDb ? "claims" : "effects"],
      { encoding: "utf8", timeout: 20_000 });
      assert.equal(r.status, 0, r.stderr);
    };
    run({ send, remove, providerDb, gateDb });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test("retained execution claim blocks duplicate effect after provider history loss", () => scenario(({ send, remove, providerDb }) => {
  const first = send();
  assert.equal(first.status, 0, first.stderr);
  remove(providerDb);
  const replay = send();
  assert.equal(replay.status, 2);
  assert.match(replay.stderr, /execution_claim_spent/);
  const status = spawnSync("python3", [provider, providerDb, "status"],
    { input: JSON.parse(first.stdout).operation_id, encoding: "utf8", timeout: 20_000 });
  assert.equal(JSON.parse(status.stdout).record, null, "gate cannot restore provider evidence");
}));

test("rollback of both provider and gate permits duplicate external effect", () => scenario(({ send, remove, providerDb, gateDb }) => {
  const first = send();
  assert.equal(first.status, 0, first.stderr);
  remove(providerDb);
  remove(gateDb);
  const second = send();
  assert.equal(second.status, 0, second.stderr);
  assert.notEqual(JSON.parse(first.stdout).effect_id, JSON.parse(second.stdout).effect_id);
}));

test("unmediated provider route bypasses a retained execution claim", () => scenario(({ send, remove, providerDb }) => {
  const first = send();
  assert.equal(first.status, 0, first.stderr);
  remove(providerDb);
  const bypass = send(null);
  assert.equal(bypass.status, 0, bypass.stderr);
  assert.notEqual(JSON.parse(first.stdout).effect_id, JSON.parse(bypass.stdout).effect_id);
}));

test("crash after gate consumption but before effect preserves safety and loses liveness", () => scenario(({ send }) => {
  const first = send(undefined, "before_commit");
  assert.equal(first.status, 76);
  const retry = send();
  assert.equal(retry.status, 2);
  assert.match(retry.stderr, /execution_claim_spent/);
}));

test("missing execution gate fails closed before provider effect", () => scenario(({ send, gateDb }) => {
  fs.unlinkSync(gateDb);
  const result = send();
  assert.equal(result.status, 2);
  assert.match(result.stderr, /OperationalError/);
}));
