import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import { signGovernanceStreamTranscript } from "../protocol/governanceTranscriptSignature.js";
import { evaluateGovernanceWitnessQuorum, verifyGovernanceWitnessQuorum } from "../protocol/governanceWitnessQuorum.js";

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map(JSON.parse);
const transcript = createGovernanceStreamTranscript(messages);

function signer(name) {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const signed = signGovernanceStreamTranscript(transcript, privateKey.export({ type: "pkcs8", format: "pem" }), { signer: name, scope: "governance-witness" });
  return signed;
}

test("2-of-3 trusted witnesses establish quorum on the same transcript", () => {
  const a = signer("witness-a");
  const b = signer("witness-b");
  const c = signer("witness-c");
  const trusted = [a, b, c].map((item) => item.signature.public_key_fingerprint_sha256);
  const result = evaluateGovernanceWitnessQuorum([a, b, c], { threshold: 2, trusted_fingerprints: trusted, required_scope: "governance-witness" });
  assert.equal(result.quorum_met, true);
  assert.equal(result.winning_witness_count, 3);
  assert.equal(result.conflicting_eligible_roots, false);
  assert.equal(verifyGovernanceWitnessQuorum(result).valid, true);
});

test("duplicate keys do not inflate a unique-key quorum", () => {
  const a = signer("witness-a");
  const trusted = [a.signature.public_key_fingerprint_sha256];
  const result = evaluateGovernanceWitnessQuorum([a, structuredClone(a)], { threshold: 2, trusted_fingerprints: trusted });
  assert.equal(result.quorum_met, false);
  assert.equal(result.witnesses[1].duplicate_key, true);
});

test("revoked witness keys are excluded", () => {
  const a = signer("witness-a");
  const b = signer("witness-b");
  const trusted = [a, b].map((item) => item.signature.public_key_fingerprint_sha256);
  const result = evaluateGovernanceWitnessQuorum([a, b], {
    threshold: 2,
    trusted_fingerprints: trusted,
    revoked_fingerprints: [b.signature.public_key_fingerprint_sha256]
  });
  assert.equal(result.quorum_met, false);
  assert.equal(result.witnesses[1].revoked_key, true);
});
