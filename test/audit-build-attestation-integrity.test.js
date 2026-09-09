import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  createAuditStream,
  appendAuditEvent,
  signAuditCheckpoint,
  verifyAuditCheckpoint,
  signBuildManifest,
  verifyBuildAttestation
} from "../index.js";

const timestamp = "2033-01-01T00:00:00.000Z";

function keys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKey,
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    fingerprint: crypto.createHash("sha256").update(publicDer).digest("hex")
  };
}

function auditStream() {
  const stream = createAuditStream({ stream_id: "attestation-integrity", timestamp });
  appendAuditEvent(stream, {
    event_type: "render",
    payload: { allowed: true }
  }, { timestamp: "2033-01-01T00:00:01.000Z" });
  return stream;
}

function tempManifest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-attestation-integrity-"));
  const manifestPath = path.join(dir, "build_manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({ version: 1, ok: true }));
  return manifestPath;
}

test("current audit checkpoint attestation cryptographically binds signer", () => {
  const key = keys();
  const stream = auditStream();
  const signed = signAuditCheckpoint(stream, key.privatePem, {
    signer: "audit-signer",
    timestamp: "2033-01-01T00:00:02.000Z"
  });

  const verification = verifyAuditCheckpoint(stream, signed);
  assert.equal(verification.verified, true);
  assert.equal(verification.attribution_bound, true);
  assert.equal(verification.signer, "audit-signer");

  const tampered = structuredClone(signed);
  tampered.attestation.signer = "forged-audit-signer";
  const rejected = verifyAuditCheckpoint(stream, tampered);
  assert.equal(rejected.verified, false);
  assert.equal(rejected.signature_valid, false);
});

test("legacy audit checkpoint signatures verify checkpoint but do not authenticate signer label", () => {
  const key = keys();
  const stream = auditStream();
  const checkpoint = {
    protocol: "ĀML Runtime Audit Checkpoint",
    version: "1.0",
    stream_id: stream.stream_id,
    entries: stream.entries.length,
    head_hash: stream.head_hash,
    checkpointed_at: "2033-01-01T00:00:02.000Z"
  };
  const signature = crypto.sign(null, Buffer.from(JSON.stringify(checkpoint)), key.privateKey);
  const legacy = {
    ...checkpoint,
    attestation: {
      algorithm: "Ed25519",
      signer: "legacy-audit-claim",
      public_key_sha256: key.fingerprint,
      public_key_pem: key.publicPem,
      signature_base64: signature.toString("base64")
    }
  };

  const verification = verifyAuditCheckpoint(stream, legacy);
  assert.equal(verification.verified, true);
  assert.equal(verification.attribution_bound, false);
  assert.equal(verification.signer, null);
  assert.equal(verification.claimed_signer, "legacy-audit-claim");

  legacy.attestation.signer = "rewritten-legacy-audit-claim";
  const relabeled = verifyAuditCheckpoint(stream, legacy);
  assert.equal(relabeled.verified, true);
  assert.equal(relabeled.attribution_bound, false);
  assert.equal(relabeled.signer, null);
  assert.equal(relabeled.claimed_signer, "rewritten-legacy-audit-claim");
});

test("malformed audit checkpoint public key fails closed", () => {
  const key = keys();
  const stream = auditStream();
  const signed = signAuditCheckpoint(stream, key.privatePem, { signer: "audit-signer", timestamp });
  signed.attestation.public_key_pem = "not a public key";

  assert.doesNotThrow(() => verifyAuditCheckpoint(stream, signed));
  const verification = verifyAuditCheckpoint(stream, signed);
  assert.equal(verification.verified, false);
  assert.equal(verification.signature_valid, false);
});

test("current build attestation binds signer, signing time, and manifest path", () => {
  const key = keys();
  const manifestPath = tempManifest();
  const signed = signBuildManifest(manifestPath, key.privatePem, {
    signer: "build-signer",
    timestamp
  });

  const verification = verifyBuildAttestation(signed, manifestPath);
  assert.equal(verification.verified, true);
  assert.equal(verification.attribution_bound, true);
  assert.equal(verification.signer, "build-signer");
  assert.equal(verification.signed_at, timestamp);

  const signerTampered = structuredClone(signed);
  signerTampered.signer = "forged-build-signer";
  assert.equal(verifyBuildAttestation(signerTampered, manifestPath).verified, false);

  const timeTampered = structuredClone(signed);
  timeTampered.signed_at = "2099-01-01T00:00:00.000Z";
  assert.equal(verifyBuildAttestation(timeTampered, manifestPath).verified, false);

  const pathTampered = structuredClone(signed);
  pathTampered.manifest_path = "/tmp/forged-manifest-path.json";
  const pathVerification = verifyBuildAttestation(pathTampered, manifestPath);
  assert.equal(pathVerification.hash_valid, true);
  assert.equal(pathVerification.signature_valid, false);
  assert.equal(pathVerification.verified, false);
});

test("legacy build signatures verify manifest bytes but do not authenticate metadata", () => {
  const key = keys();
  const manifestPath = tempManifest();
  const manifest = fs.readFileSync(manifestPath);
  const manifestHash = crypto.createHash("sha256").update(manifest).digest("hex");
  const signature = crypto.sign(null, manifest, key.privateKey);
  const legacy = {
    protocol: "ĀML Build Attestation",
    version: "1.0",
    algorithm: "Ed25519",
    manifest_path: manifestPath,
    manifest_sha256: manifestHash,
    public_key_sha256: key.fingerprint,
    public_key_pem: key.publicPem,
    signature_base64: signature.toString("base64"),
    signed_at: timestamp,
    signer: "legacy-build-claim"
  };

  const verification = verifyBuildAttestation(legacy, manifestPath);
  assert.equal(verification.verified, true);
  assert.equal(verification.attribution_bound, false);
  assert.equal(verification.signer, null);
  assert.equal(verification.signed_at, null);
  assert.equal(verification.claimed_signer, "legacy-build-claim");
  assert.equal(verification.claimed_signed_at, timestamp);

  legacy.signer = "rewritten-legacy-build-claim";
  legacy.signed_at = "2099-01-01T00:00:00.000Z";
  const relabeled = verifyBuildAttestation(legacy, manifestPath);
  assert.equal(relabeled.verified, true);
  assert.equal(relabeled.attribution_bound, false);
  assert.equal(relabeled.signer, null);
  assert.equal(relabeled.claimed_signer, "rewritten-legacy-build-claim");
});

test("malformed build attestation key and missing manifest fail closed", () => {
  const key = keys();
  const manifestPath = tempManifest();
  const signed = signBuildManifest(manifestPath, key.privatePem, { signer: "build-signer", timestamp });

  const badKey = structuredClone(signed);
  badKey.public_key_pem = "not a public key";
  assert.doesNotThrow(() => verifyBuildAttestation(badKey, manifestPath));
  assert.equal(verifyBuildAttestation(badKey, manifestPath).verified, false);

  assert.doesNotThrow(() => verifyBuildAttestation(signed, `${manifestPath}.missing`));
  assert.equal(verifyBuildAttestation(signed, `${manifestPath}.missing`).verified, false);
});
