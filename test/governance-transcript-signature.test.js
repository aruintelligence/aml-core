import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import {
  signGovernanceStreamTranscript,
  verifySignedGovernanceStreamTranscript
} from "../protocol/governanceTranscriptSignature.js";

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/)
  .map(line => line.trim())
  .filter(Boolean)
  .map(line => JSON.parse(line));

function keys() {
  return crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
}

test("valid governance transcript can be signed and verified", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const pair = keys();
  const signed = signGovernanceStreamTranscript(transcript, pair.privateKey, {
    key_id: "test-key-1",
    signer: "test-suite",
    signed_at: "2026-09-10T00:00:00.000Z"
  });
  const verification = verifySignedGovernanceStreamTranscript(signed);
  assert.equal(verification.valid, true);
  assert.equal(verification.signature_valid, true);
  assert.equal(verification.transcript_valid, true);
  assert.equal(verification.trusted_key, false);
});

test("trusted fingerprint requirement is separate from signature validity", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const pair = keys();
  const signed = signGovernanceStreamTranscript(transcript, pair.privateKey, { key_id: "test-key-2" });

  const untrusted = verifySignedGovernanceStreamTranscript(signed, { require_trusted_key: true });
  assert.equal(untrusted.signature_valid, true);
  assert.equal(untrusted.trusted_key, false);
  assert.equal(untrusted.valid, false);

  const trusted = verifySignedGovernanceStreamTranscript(signed, {
    require_trusted_key: true,
    trusted_fingerprints: [signed.signature.public_key_fingerprint_sha256]
  });
  assert.equal(trusted.valid, true);
  assert.equal(trusted.trusted_key, true);
});

test("signed transcript rejects transcript mutation", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const pair = keys();
  const signed = signGovernanceStreamTranscript(transcript, pair.privateKey);
  const tampered = structuredClone(signed);
  tampered.transcript.entries[1].message.accepted = false;
  const verification = verifySignedGovernanceStreamTranscript(tampered);
  assert.equal(verification.valid, false);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.transcript_valid, false);
});

test("signed transcript rejects signature substitution", () => {
  const transcript = createGovernanceStreamTranscript(messages);
  const first = keys();
  const second = keys();
  const signed = signGovernanceStreamTranscript(transcript, first.privateKey);
  const otherSigned = signGovernanceStreamTranscript(transcript, second.privateKey);
  signed.signature.signature_base64 = otherSigned.signature.signature_base64;
  const verification = verifySignedGovernanceStreamTranscript(signed);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.valid, false);
});
