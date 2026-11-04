import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runLocalOutboxReference } from "../AML_AGENT_INTEGRATION_REFERENCE/local-outbox.mjs";

test("local function tool binds approval, rejects tamper/replay, and records uncertain effect", async () => {
  const report = await runLocalOutboxReference();
  assert.deepEqual(report.cases.map(row => row.receipt.execution_status),
    ["blocked", "blocked", "dispatched", "blocked", "unknown"]);
  assert.deepEqual(report.cases.map(row => row.local_records_after_case), [0, 0, 1, 1, 2]);
  assert.equal(report.callback_count, 2);
  assert.match(report.local_observation_sha256, /^[a-f0-9]{64}$/);
  const published = JSON.parse(readFileSync(new URL("../AML_AGENT_INTEGRATION_REFERENCE/report.json", import.meta.url)));
  assert.deepEqual(report, published);
});
