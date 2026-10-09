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
  assert.equal(denied.headers.get("www-authenticate"), 'Bearer realm="aml"');
  assert.match(denied.headers.get("content-type"), /application\/json/);
  assert.equal((await denied.json()).error, "unauthorized");
  const allowed = await request(`Bearer ${token}`);
  assert.equal(allowed.status, 200);
  const lines = (await allowed.text()).trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(lines.at(-1).protocol, "aml-governance-stream-result/1");
});

test("governance stream bounds stalled authentication before opening NDJSON", async (t) => {
  const server = createGovernanceStreamGateway({ auth_timeout_ms: 20, request_auth: () => new Promise(() => {}) });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/governance/stream`, {
    method: "POST", body: fixture
  });
  assert.equal(response.status, 503);
  assert.match(response.headers.get("content-type"), /application\/json/);
  assert.equal((await response.json()).error, "authentication_unavailable");
});

test("governance stream gateway rejects excess in-flight work before opening NDJSON", async (t) => {
  let release;
  let entered;
  const held = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  const server = createGovernanceStreamGateway({
    max_inflight_requests: 1,
    request_auth: async () => { entered(); await held; return true; }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/v1/governance/stream`;
  const post = () => fetch(url, { method: "POST", body: fixture });
  const first = post();
  await started;
  const overloaded = await post();
  assert.equal(overloaded.status, 503);
  assert.match(overloaded.headers.get("content-type"), /application\/json/);
  assert.equal((await overloaded.json()).error, "server_busy");
  release();
  const accepted = await first;
  assert.equal(accepted.status, 200);
  await accepted.text();
  const retry = await post();
  assert.equal(retry.status, 200);
  await retry.text();
});

test("governance stream locked policy rejects open, node, and transition overrides", async (t) => {
  const server = createGovernanceStreamGateway({
    request_auth: { bearer_token: token },
    locked_policy: { profile: "calm_default" }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/v1/governance/stream`;
  const [fixtureOpen, firstNode, secondNode, finalize] = fixture.trim().split(/\r?\n/).map(line => JSON.parse(line));
  const open = { protocol: fixtureOpen.protocol, transmission: fixtureOpen.transmission };
  const request = async (messages) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/x-ndjson", authorization: `Bearer ${token}` },
      body: `${messages.map(message => JSON.stringify(message)).join("\n")}\n`
    });
    if (response.status !== 200) {
      return { status: response.status, messages: [await response.json()] };
    }
    return {
      status: response.status,
      messages: (await response.text()).trim().split(/\r?\n/).map(line => JSON.parse(line))
    };
  };

  const openedWithOverride = await request([{ ...open, mode: "shadow" }, firstNode, finalize]);
  assert.equal(openedWithOverride.status, 403);
  assert.equal(openedWithOverride.messages[0].protocol, "aml-governance-stream-error/1");
  assert.equal(openedWithOverride.messages[0].error, "policy_override_forbidden");

  const nodeOverride = await request([open, { ...firstNode, failure_mode: "open" }, finalize]);
  assert.equal(nodeOverride.status, 200);
  assert.equal(nodeOverride.messages[0].policy_source, "server");
  assert.equal(nodeOverride.messages.at(-1).error, "policy_override_forbidden");
  assert.equal(nodeOverride.messages.some(message => message.protocol === "aml-governance-stream-decision/1"), false);

  const transition = await request([open, { protocol: "aml-governance-stream-policy-update/1", mode: "shadow" }, finalize]);
  assert.equal(transition.status, 200);
  assert.equal(transition.messages.at(-1).error, "policy_override_forbidden");

  const valid = await request([open, firstNode, secondNode, finalize]);
  assert.equal(valid.status, 200);
  assert.equal(valid.messages[0].mode, "enforce");
  assert.equal(valid.messages[0].failure_mode, "closed");
  assert.equal(valid.messages.at(-1).protocol, "aml-governance-stream-result/1");
  assert.equal(valid.messages.at(-1).suppressed, 1);
});

test("governance stream gateway rejects advertised oversized uploads with a readable 413", async (t) => {
  const server = createGovernanceStreamGateway({ max_stream_bytes: 32 });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/governance/stream`, {
    method: "POST",
    headers: { "content-type": "application/x-ndjson" },
    body: fixture
  });
  assert.equal(response.status, 413);
  assert.equal(response.headers.get("connection"), "close");
  assert.equal((await response.json()).error, "governance stream exceeds max_stream_bytes");
});

test("governance stream gateway rejects an overlong first line before opening NDJSON", async (t) => {
  const server = createGovernanceStreamGateway({ max_line_bytes: 16 });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/governance/stream`, {
    method: "POST",
    headers: { "content-type": "application/x-ndjson" },
    body: fixture
  });
  assert.equal(response.status, 413);
  assert.equal((await response.json()).error, "governance stream line exceeds max_line_bytes");
});

test("governance stream gateway enforces a message ceiling after accepting open", async (t) => {
  const server = createGovernanceStreamGateway({ max_messages: 2 });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/governance/stream`, {
    method: "POST",
    headers: { "content-type": "application/x-ndjson" },
    body: fixture
  });
  assert.equal(response.status, 200);
  const messages = (await response.text()).trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(messages[0].accepted, true);
  assert.equal(messages.at(-1).protocol, "aml-governance-stream-error/1");
  assert.equal(messages.at(-1).error, "governance stream exceeds max_messages");
  assert.equal(messages.some(message => message.protocol === "aml-governance-stream-result/1"), false);
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
