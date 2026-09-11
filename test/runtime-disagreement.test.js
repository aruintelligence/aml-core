import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import { localizeRuntimeDisagreement } from "../protocol/runtimeDisagreement.js";

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/)
  .map(line => line.trim())
  .filter(Boolean)
  .map(line => JSON.parse(line));

test("identical runtime transcripts are equivalent", () => {
  const left = createGovernanceStreamTranscript(messages);
  const right = structuredClone(left);
  const report = localizeRuntimeDisagreement(left, right, { left_runtime: "runtime-a", right_runtime: "runtime-b" });
  assert.equal(report.equivalent, true);
  assert.equal(report.first_divergence, null);
  assert.equal(report.same_root, true);
});

test("localizes the first decision disagreement", () => {
  const left = createGovernanceStreamTranscript(messages);
  const right = structuredClone(left);
  const index = right.entries.findIndex(entry => entry.direction === "output" && entry.message?.protocol === "aml-governance-stream-decision/1");
  right.entries[index].message.aml_allowed = !right.entries[index].message.aml_allowed;
  const report = localizeRuntimeDisagreement(left, right);
  assert.equal(report.equivalent, false);
  assert.equal(report.first_divergence.sequence, index + 1);
  assert.equal(report.first_divergence.divergence_type, "decision-mismatch");
  assert.notEqual(report.first_divergence.left_sha256, report.first_divergence.right_sha256);
});

test("localizes missing output caused by early runtime termination", () => {
  const left = createGovernanceStreamTranscript(messages);
  const right = structuredClone(left);
  right.entries.pop();
  const report = localizeRuntimeDisagreement(left, right);
  assert.equal(report.equivalent, false);
  assert.equal(report.first_divergence.divergence_type, "missing-entry");
});
