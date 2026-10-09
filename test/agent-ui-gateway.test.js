import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { createAgentUiGateway } from "../server/agentUiGateway.js";

const vector = JSON.parse(fs.readFileSync("conformance/agent-ui/mixed.json", "utf8"));
const token = "0123456789abcdef0123456789abcdef0123456789abcdef";

test("Agent UI HTTP gateway authenticates POST requests", async (t) => {
  const server = createAgentUiGateway({ request_auth: { bearer_token: token } });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${base}/health`)).status, 200);
  const request = (authorization) => fetch(`${base}/v1/agent-ui/evaluate`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(authorization ? { authorization } : {})
    },
    body: JSON.stringify({ envelope: vector, timestamp: "2026-09-10T00:00:00.000Z" })
  });
  const denied = await request();
  assert.equal(denied.status, 401);
  assert.equal((await denied.json()).error, "unauthorized");
  const allowed = await request(`Bearer ${token}`);
  assert.equal(allowed.status, 200);
  assert.equal((await allowed.json()).protocol, "aml-agent-ui-governance-result/1");
});

test("Agent UI locked policy rejects caller controls and selects enforce/closed on the server", async (t) => {
  const server = createAgentUiGateway({
    request_auth: { bearer_token: token },
    locked_policy: { profile: "calm_default", context: { attention_budget_remaining: 10 } }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/v1/agent-ui/evaluate`;
  const evaluate = (body) => fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(body)
  });
  for (const override of [{ mode: "shadow" }, { failure_mode: "open" }, { context: null }, { timestamp: null }]) {
    const denied = await evaluate({ envelope: vector, ...override });
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).error, "policy_override_forbidden");
  }
  const allowed = await evaluate({ envelope: vector });
  assert.equal(allowed.status, 200);
  const result = await allowed.json();
  assert.equal(result.policy_source, "server");
  assert.equal(result.mode, "enforce");
  assert.equal(result.allowed, 1);
  assert.equal(result.suppressed, 1);
});

test("Agent UI HTTP gateway returns a readable 413 for oversized JSON", async (t) => {
  const server = createAgentUiGateway({ max_body_bytes: 32 });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/agent-ui/evaluate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ envelope: vector })
  });
  assert.equal(response.status, 413);
  assert.equal(response.headers.get("connection"), "close");
  assert.equal((await response.json()).error, "request_too_large");
});

test("Agent UI CLI produces deterministic mixed governance result", () => {
  const run = spawnSync(process.execPath, ["bin/aml-agent-ui.js", "conformance/agent-ui/mixed.json", "--timestamp", "2026-09-10T00:00:00.000Z"], {
    encoding: "utf8"
  });
  assert.equal(run.status, 0, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.protocol, "aml-agent-ui-governance-result/1");
  assert.equal(result.total, 2);
  assert.equal(result.allowed, 1);
  assert.equal(result.suppressed, 1);
  assert.deepEqual(result.renderable_components.map(item => item.id), ["continue"]);
  assert.deepEqual(result.suppressed_components.map(item => item.id), ["pressure"]);
});

test("Agent UI HTTP gateway exposes the same protocol boundary", async (t) => {
  const server = createAgentUiGateway({ default_profile: "calm_default" });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/agent-ui/evaluate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ envelope: vector, timestamp: "2026-09-10T00:00:00.000Z" })
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.protocol, "aml-agent-ui-governance-result/1");
  assert.equal(result.allowed, 1);
  assert.equal(result.suppressed, 1);
});

test("Agent UI gateway rejects missing governance metadata", async (t) => {
  const server = createAgentUiGateway();
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/agent-ui/evaluate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocol: "aml-agent-ui-envelope/1", components: [{ id: "unsafe", type: "button" }] })
  });
  assert.equal(response.status, 400);
  const result = await response.json();
  assert.equal(result.protocol, "aml-agent-ui-gateway-error/1");
  assert.match(result.error, /governance/);
});
