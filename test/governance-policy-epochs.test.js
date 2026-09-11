import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  createGovernanceStreamSession,
  AML_GOVERNANCE_STREAM_POLICY_APPLIED
} from "../protocol/governanceStream.js";
import { createGovernanceStreamTranscript, verifyGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";

const messages = fs.readFileSync("conformance/governance-stream/policy-epochs.ndjson", "utf8")
  .split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => JSON.parse(line));

test("live policy updates become explicit policy epochs", () => {
  const session = createGovernanceStreamSession(messages[0]);
  const first = session.accept(messages[1]);
  assert.equal(first.protocol, AML_GOVERNANCE_STREAM_POLICY_APPLIED);
  assert.equal(first.policy_epoch, 1);
  assert.equal(first.mode, "shadow");
  assert.match(first.policy_sha256, /^[a-f0-9]{64}$/);

  const pressure = session.accept(messages[2]);
  assert.equal(pressure.aml_allowed, false);
  assert.equal(pressure.effective_allowed, true);

  const second = session.accept(messages[3]);
  assert.equal(second.policy_epoch, 2);
  assert.equal(second.mode, "enforce");

  const allowed = session.accept(messages[4]);
  assert.equal(allowed.aml_allowed, true);
  assert.equal(allowed.effective_allowed, true);

  const final = session.accept(messages[5]);
  assert.equal(final.policy_epochs, 2);
  assert.match(final.final_policy_sha256, /^[a-f0-9]{64}$/);
});

test("policy epoch streams remain deterministically replayable", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const verification = verifyGovernanceStreamTranscript(transcript);
  assert.equal(verification.valid, true);
  assert.equal(verification.replay_valid, true);
});

test("invalid policy transitions are rejected before a node is evaluated", () => {
  const session = createGovernanceStreamSession(messages[0]);
  assert.throws(() => session.accept({ protocol: "aml-governance-stream-policy-update/1", mode: "maybe" }), /mode must be enforce or shadow/);
});
