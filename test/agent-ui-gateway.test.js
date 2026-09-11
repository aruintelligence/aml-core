import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { createAgentUiGateway } from "../server/agentUiGateway.js";

const vector = JSON.parse(fs.readFileSync("conformance/agent-ui/mixed.json", "utf8"));

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
