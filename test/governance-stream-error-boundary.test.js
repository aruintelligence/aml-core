import test from "node:test";
import assert from "node:assert/strict";
import { createGovernanceStreamGateway } from "../server/governanceStreamGateway.js";

const canary = "SYNTHETIC_PRIVATE_DETAIL_CANARY";
const open = { protocol: "aml-governance-stream-open/1" };
async function request({ fault, afterOpen = false, options = {}, body = JSON.stringify(open) + "\n" } = {}) {
  const server = createGovernanceStreamGateway(options);
  if (fault) server.prependListener("request", req => {
    req[Symbol.asyncIterator] = async function* () {
      if (afterOpen) yield Buffer.from(JSON.stringify(open) + "\n");
      throw fault();
    };
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    const r = await fetch(`http://127.0.0.1:${server.address().port}/v1/governance/stream`, { method: "POST", body });
    return { status: r.status, text: await r.text() };
  } finally { await new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }); }
}
for (const [name, fault] of [
  ["ordinary", () => new Error(canary)],
  ["stack-text", () => new Error(`${canary}\n    at synthetic (/private/path:1:2)`) ],
  ["forged status", () => Object.assign(new Error(canary), { statusCode: 503 })],
  ["primitive", () => canary], ["null", () => null],
  ["throwing getters", () => ({ get message() { throw new Error(canary); }, get code() { throw new Error(canary); }, toString() { throw new Error(canary); } })]
]) {
  test(`unexpected reader ${name}: generic response before and after headers, no details`, async () => {
    for (const afterOpen of [false, true]) {
      const result = await request({ fault, afterOpen });
      assert.equal(result.status, afterOpen ? 200 : 400);
      assert.doesNotMatch(result.text, /CANARY|private\/path|\bat synthetic|stack/);
      const rows = result.text.trim().split("\n").map(line => JSON.parse(line));
      assert.equal(rows.at(-1).protocol, "aml-governance-stream-error/1");
      assert.equal(rows.at(-1).error, "governance_stream_failed");
      assert.equal(rows.some(r => r.protocol === "aml-governance-stream-result/1"), false);
    }
  });
}
test("malformed JSON uses fixed client code, never parser diagnostics", async () => {
  const r = await request({ body: `{${canary}}\n` });
  assert.equal(r.status, 400); assert.equal(JSON.parse(r.text).error, "invalid_json"); assert.ok(!r.text.includes(canary));
});
test("allowlisted protocol prefix returns only fixed code, not its arbitrary suffix", async () => {
  const r = await request({ fault: () => new Error("AML_STREAM_DUPLICATE_IDENTIFIER:" + canary) });
  assert.equal(r.status, 400); assert.equal(JSON.parse(r.text).error, "AML_STREAM_DUPLICATE_IDENTIFIER"); assert.ok(!r.text.includes(canary));
});
test("auth and trusted-context failures retain stable503 codes without private details", async () => {
  for (const [options, code] of [[{ request_auth: () => { throw new Error(canary); } }, "authentication_unavailable"],
    [{ locked_policy: { resolve_context: () => { throw new Error(canary); } } }, "trusted_context_unavailable"]]) {
    const r = await request({ options }); assert.equal(r.status, 503);
    assert.equal(JSON.parse(r.text).error, code); assert.ok(!r.text.includes(canary));
  }
});
