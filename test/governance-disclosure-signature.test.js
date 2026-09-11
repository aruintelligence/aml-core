import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import { createGovernanceDisclosure } from "../protocol/governanceDisclosure.js";
import {
  signGovernanceDisclosureCommitment,
  verifySignedGovernanceDisclosureCommitment,
  verifyGovernanceDisclosureAgainstSignedCommitment
} from "../protocol/governanceDisclosureSignature.js";

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => JSON.parse(line));

function fixture() {
  const transcript = createGovernanceStreamTranscript(messages);
  const disclosure = createGovernanceDisclosure(transcript, [1, 4]);
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const signed = signGovernanceDisclosureCommitment(disclosure, privatePem, { signer: "test-witness" });
  return { transcript, disclosure, signed };
}

test("trusted signed commitment authenticates a selective disclosure", () => {
  const { disclosure, signed } = fixture();
  const fingerprint = signed.signature.public_key_fingerprint_sha256;
  const result = verifyGovernanceDisclosureAgainstSignedCommitment(disclosure, signed, {
    trusted_fingerprints: [fingerprint],
    require_trusted_key: true,
    required_scope: "governance-disclosure-commitment"
  });
  assert.equal(result.valid, true);
  assert.equal(result.signature_valid, true);
  assert.equal(result.trusted_key, true);
  assert.equal(result.disclosure_valid, true);
});

test("valid signature does not imply trusted key", () => {
  const { signed } = fixture();
  const result = verifySignedGovernanceDisclosureCommitment(signed, { require_trusted_key: true });
  assert.equal(result.signature_valid, true);
  assert.equal(result.trusted_key, false);
  assert.equal(result.valid, false);
});

test("revoked key is rejected by verifier policy", () => {
  const { disclosure, signed } = fixture();
  const fingerprint = signed.signature.public_key_fingerprint_sha256;
  const result = verifyGovernanceDisclosureAgainstSignedCommitment(disclosure, signed, {
    trusted_fingerprints: [fingerprint],
    revoked_fingerprints: [fingerprint],
    require_trusted_key: true
  });
  assert.equal(result.valid, false);
  assert.equal(result.trusted_key, false);
});

test("commitment substitution invalidates the signature", () => {
  const { signed } = fixture();
  signed.commitment.disclosure_merkle_root_sha256 = "0".repeat(64);
  const result = verifySignedGovernanceDisclosureCommitment(signed);
  assert.equal(result.signature_valid, false);
  assert.equal(result.valid, false);
});
