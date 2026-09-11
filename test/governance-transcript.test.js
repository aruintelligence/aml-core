import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import {
  createGovernanceStreamTranscript,
  verifyGovernanceStreamTranscript
} from "../protocol/governanceTranscript.js";

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/)
  .map(line => line.trim())
  .filter(Boolean)
  .map(line => JSON.parse(line));

test("governance transcript is hash chained and replay verifiable", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  assert.equal(transcript.protocol, "aml-governance-stream-transcript/1");
  assert.equal(transcript.entry_count, 8);
  assert.match(transcript.root_sha256, /^[a-f0-9]{64}$/);
  const verification = verifyGovernanceStreamTranscript(transcript);
  assert.equal(verification.valid, true);
  assert.equal(verification.hash_chain_valid, true);
  assert.equal(verification.replay_valid, true);
});

test("governance transcript detects recorded decision tampering", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const tampered = structuredClone(transcript);
  const decision = tampered.entries.find(entry => entry.direction === "output" && entry.message.protocol === "aml-governance-stream-decision/1");
  decision.message.aml_allowed = !decision.message.aml_allowed;
  const verification = verifyGovernanceStreamTranscript(tampered);
  assert.equal(verification.valid, false);
  assert.equal(verification.hash_chain_valid, false);
});

test("governance transcript detects internally rehashed false output by deterministic replay", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const inputMessages = transcript.entries.filter(entry => entry.direction === "input").map(entry => entry.message);
  const fake = createGovernanceStreamTranscript(inputMessages);
  const decisionIndex = fake.entries.findIndex(entry => entry.direction === "output" && entry.message.protocol === "aml-governance-stream-decision/1");
  fake.entries[decisionIndex].message.would_suppress = !fake.entries[decisionIndex].message.would_suppress;

  let previous = null;
  for (let index = 0; index < fake.entries.length; index += 1) {
    const entry = fake.entries[index];
    entry.sequence = index + 1;
    entry.previous_sha256 = previous;
    const material = { sequence: entry.sequence, direction: entry.direction, previous_sha256: entry.previous_sha256, message: entry.message };
    entry.entry_sha256 = crypto.createHash("sha256").update(canonicalJSONStringify(material)).digest("hex");
    previous = entry.entry_sha256;
  }
  fake.root_sha256 = previous;

  const verification = verifyGovernanceStreamTranscript(fake);
  assert.equal(verification.hash_chain_valid, true);
  assert.equal(verification.replay_valid, false);
  assert.equal(verification.valid, false);
});

test("transcript generator CLI emits a verifiable artifact", () => {
  const run = spawnSync(process.execPath, ["bin/aml-governance-transcript.js", "conformance/governance-stream/mixed.ndjson"], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const transcript = JSON.parse(run.stdout);
  const verify = spawnSync(process.execPath, ["bin/aml-governance-transcript-verify.js"], {
    input: JSON.stringify(transcript),
    encoding: "utf8"
  });
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).valid, true);
});
