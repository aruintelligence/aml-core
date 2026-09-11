import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import { createGovernanceDisclosure, verifyGovernanceDisclosure } from "../protocol/governanceDisclosure.js";

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => JSON.parse(line));

test("selectively discloses transcript entries with valid Merkle proofs", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const disclosure = createGovernanceDisclosure(transcript, [1, 4]);
  const result = verifyGovernanceDisclosure(disclosure, {
    expected_merkle_root: disclosure.disclosure_merkle_root_sha256,
    expected_transcript_root: transcript.root_sha256
  });
  assert.equal(result.valid, true);
  assert.equal(result.disclosed_count, 2);
  assert.equal(result.externally_anchored, true);
});

test("rejects a modified disclosed message", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const disclosure = createGovernanceDisclosure(transcript, [2]);
  disclosure.disclosed_entries[0].entry.message.aml_allowed = !disclosure.disclosed_entries[0].entry.message.aml_allowed;
  const result = verifyGovernanceDisclosure(disclosure);
  assert.equal(result.valid, false);
});

test("rejects an unexpected external commitment", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const disclosure = createGovernanceDisclosure(transcript, [0]);
  const result = verifyGovernanceDisclosure(disclosure, { expected_merkle_root: "0".repeat(64) });
  assert.equal(result.valid, false);
});
