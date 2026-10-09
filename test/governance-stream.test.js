import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { createGovernanceStreamGateway } from "../server/governanceStreamGateway.js";

const fixture = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8");
const token = "0123456789abcdef0123456789abcdef0123456789abcdef";

test("governance stream HTTP authenticates before opening the NDJSON response", async (t) => {
  const server = createGovernanceStreamGateway({ request_auth: { bearer_token: token } });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${base}/health`)).status, 200);
  const request = (authorization) => fetch(`${base}/v1/governance/stream`, {
    method: "POST",
    headers: {
      "content-type": "application/x-ndjson",
      ...(authorization ? { authorization } : {})
    },
    body: fixture
  });
  const denied = await request();
  assert.equal(denied.status, 401);
  assert.match(denied.headers.get("content-type"), /application\/json/);
  assert.equal((await denied.json()).error, "unauthorized");
  const allowed = await request(`Bearer ${token}`);
  assert.equal(allowed.status, 200);
  const lines = (await allowed.text()).trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(lines.at(-1).protocol, "aml-governance-stream-result/1");
});

test("governance stream CLI emits open, two decisions, and final result", () => {
  const run = spawnSync(process.execPath, ["bin/aml-governance-stream.js", "conformance/governance-stream/mixed.ndjson"], {
    encoding: "utf8"
  });
  assert.equal(run.status, 0, run.stderr);
  const lines = run.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(lines.length, 4);
  assert.equal(lines[0].protocol, "aml-governance-stream-open/1");
  assert.equal(lines[1].protocol, "aml-governance-stream-decision/1");
  assert.equal(lines[1].aml_allowed, false);
  assert.equal(lines[2].aml_allowed, true);
  assert.equal(lines[3].protocol, "aml-governance-stream-result/1");
  assert.equal(lines[3].total, 2);
  assert.equal(lines[3].allowed, 1);
  assert.equal(lines[3].suppressed, 1);
});

test("governance stream HTTP gateway emits NDJSON decisions before final summary", async (t) => {
  const server = createGovernanceStreamGateway();
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const address = server.address();

  const response = await fetch(`http://127.0.0.1:${address.port}/v1/governance/stream`, {
    method: "POST",
    headers: { "content-type": "application/x-ndjson" },
    body: fixture
  });

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /application\/x-ndjson/);
  const lines = (await response.text()).trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(lines[1].identifier, "pressure");
  assert.equal(lines[1].would_suppress, true);
  assert.equal(lines[2].identifier, "continue");
  assert.equal(lines[2].effective_allowed, true);
  assert.equal(lines.at(-1).protocol, "aml-governance-stream-result/1");
});

test("governance stream rejects duplicate identifiers", () => {
  const duplicated = fixture.replace(
    '"identifier":"continue"',
    '"identifier":"pressure"'
  );
  const run = spawnSync(process.execPath, ["bin/aml-governance-stream.js"], {
    input: duplicated,
    encoding: "utf8"
  });
  assert.equal(run.status, 1);
  const lines = run.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(lines.at(-1).protocol, "aml-governance-stream-error/1");
  assert.match(lines.at(-1).error, /DUPLICATE_IDENTIFIER/);
});
