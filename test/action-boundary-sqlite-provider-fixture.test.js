import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const worker = fileURLToPath(new URL("../pilots/action-boundary/sqlite-provider-fixture.py", import.meta.url));
function fixture(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-sqlite-provider-"));
  const database = path.join(directory, "provider.sqlite");
  const call = (command, input) => spawnSync("python3", [worker, database, command,
    ...(command === "request" ? ["--diagnostic-only-unguarded"] : [])],
    { encoding: "utf8", input, timeout: 20_000 });
  const bytes = JSON.stringify({ operation_id: crypto.randomUUID(),
    destination: "fixture:outbox", body: "approved" });
  const request = { request_bytes: bytes,
    request_sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
  const operation = JSON.parse(bytes).operation_id;
  try { run({ call, request, operation, database }); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test("lost response after provider commit remains uncertain until status query", () => fixture(({ call, request, operation }) => {
  const sent = call("request", JSON.stringify({ ...request, fault: "after_commit" }));
  assert.equal(sent.status, 75);
  assert.equal(sent.stdout, "");
  const recovered = call("status", operation);
  assert.equal(recovered.status, 0, recovered.stderr);
  const record = JSON.parse(recovered.stdout).record;
  assert.equal(record.operation_id, operation);
  assert.equal(record.request_sha256, request.request_sha256);
  assert.ok(record.effect_id);
  const duplicate = call("request", JSON.stringify(request));
  assert.equal(duplicate.status, 0, duplicate.stderr);
  assert.equal(JSON.parse(duplicate.stdout).effect_id, record.effect_id);
  assert.equal(JSON.parse(duplicate.stdout).diagnostic_only_unguarded, true);
}));

test("loss before provider commit remains uncertain until status query", () => fixture(({ call, request, operation }) => {
  assert.equal(call("request", JSON.stringify({ ...request, fault: "before_commit" })).status, 76);
  const status = call("status", operation);
  assert.equal(status.status, 0, status.stderr);
  assert.equal(JSON.parse(status.stdout).record, null);
  // The fixture observes no row; absence is meaningful only under its complete
  // database-view assumption. The host cannot infer universal nonexecution.
}));

test("same operation ID with changed destination or payload is rejected", () => fixture(({ call, request, operation }) => {
  assert.equal(call("request", JSON.stringify(request)).status, 0);
  for (const change of [{ destination: "fixture:other" }, { body: "tampered" }]) {
    const bytes = JSON.stringify({ ...JSON.parse(request.request_bytes), ...change });
    const changed = { request_bytes: bytes,
      request_sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
    const result = call("request", JSON.stringify(changed));
    assert.equal(result.status, 2);
    assert.match(result.stderr, /operation_request_conflict/);
  }
  assert.equal(JSON.parse(call("status", operation).stdout).record.request_sha256,
    request.request_sha256);
}));
