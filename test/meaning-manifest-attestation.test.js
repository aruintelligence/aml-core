import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  createMeaningManifest,
  verifyMeaningManifestIntegrity,
  signMeaningManifest,
  verifySignedMeaningManifest
} from "../index.js";

const sources = {
  "ui/home.aml": `transmission "home" {
    engram card {
      purpose: "Explain clearly"
      attention_cost: 2
      restoration_value: 5
    }
  }`,
  "ui/settings.aml": `transmission "settings" {
    engram privacy {
      purpose: "Expose privacy controls"
      attention_cost: 1
      restoration_value: 6
    }
  }`
};

function keys() {
  return crypto.generateKeyPairSync("ed25519");
}

function clone(value) {
  return structuredClone(value);
}

test("Meaning Manifest integrity independently verifies its semantic root", () => {
  const manifest = createMeaningManifest(sources);
  const result = verifyMeaningManifestIntegrity(manifest);
  assert.equal(result.verified, true);
  assert.equal(result.declared_root_sha256, manifest.root_sha256);
  assert.equal(result.expected_root_sha256, manifest.root_sha256);
});

test("signed Meaning Manifest binds semantic root, signer, time, and contract metadata", () => {
  const manifest = createMeaningManifest(sources);
  const { privateKey } = keys();
  const attestation = signMeaningManifest(manifest, privateKey.export({ type: "pkcs8", format: "pem" }), {
    signer: "release-engineering",
    timestamp: "2026-09-08T23:15:00.000Z"
  });

  const result = verifySignedMeaningManifest(attestation, manifest);
  assert.equal(result.verified, true);
  assert.equal(result.manifest_integrity_valid, true);
  assert.equal(result.manifest_binding_valid, true);
  assert.equal(result.signature_valid, true);
  assert.equal(result.public_key_fingerprint_valid, true);
  assert.equal(result.attribution_bound, true);
  assert.equal(result.signer, "release-engineering");
  assert.equal(result.signed_at, "2026-09-08T23:15:00.000Z");
});

test("relabeling signed attribution invalidates the attestation", () => {
  const manifest = createMeaningManifest(sources);
  const { privateKey } = keys();
  const attestation = signMeaningManifest(manifest, privateKey.export({ type: "pkcs8", format: "pem" }), {
    signer: "alice",
    timestamp: "2026-09-08T23:15:00.000Z"
  });

  const signerTamper = clone(attestation);
  signerTamper.signer = "mallory";
  const signerResult = verifySignedMeaningManifest(signerTamper, manifest);
  assert.equal(signerResult.verified, false);
  assert.equal(signerResult.signature_valid, false);
  assert.equal(signerResult.attribution_bound, false);
  assert.equal(signerResult.signer, null);

  const timeTamper = clone(attestation);
  timeTamper.signed_at = "2026-09-09T00:00:00.000Z";
  const timeResult = verifySignedMeaningManifest(timeTamper, manifest);
  assert.equal(timeResult.verified, false);
  assert.equal(timeResult.signature_valid, false);
  assert.equal(timeResult.signed_at, null);
});

test("swapping manifest identity metadata invalidates signed binding", () => {
  const manifest = createMeaningManifest(sources);
  const { privateKey } = keys();
  const attestation = signMeaningManifest(manifest, privateKey.export({ type: "pkcs8", format: "pem" }), {
    signer: "release-engineering",
    timestamp: "2026-09-08T23:15:00.000Z"
  });

  for (const mutate of [
    a => { a.manifest_root_sha256 = "0".repeat(64); },
    a => { a.file_count += 1; },
    a => { a.manifest_version = "999"; },
    a => { a.fingerprint_protocol = "other"; }
  ]) {
    const tampered = clone(attestation);
    mutate(tampered);
    const result = verifySignedMeaningManifest(tampered, manifest);
    assert.equal(result.verified, false);
    assert.equal(result.manifest_binding_valid, false);
    assert.equal(result.attribution_bound, false);
  }
});

test("signer refuses an internally inconsistent Meaning Manifest", () => {
  const manifest = createMeaningManifest(sources);
  manifest.files[0].fingerprint = "0".repeat(64);
  const { privateKey } = keys();
  assert.equal(verifyMeaningManifestIntegrity(manifest).verified, false);
  assert.throws(
    () => signMeaningManifest(manifest, privateKey.export({ type: "pkcs8", format: "pem" })),
    /Cannot sign invalid Meaning Manifest/
  );
});

test("malformed public key and signature fail closed without throwing", () => {
  const manifest = createMeaningManifest(sources);
  const { privateKey } = keys();
  const attestation = signMeaningManifest(manifest, privateKey.export({ type: "pkcs8", format: "pem" }), {
    signer: "release-engineering",
    timestamp: "2026-09-08T23:15:00.000Z"
  });

  const badKey = clone(attestation);
  badKey.public_key_pem = "not a key";
  assert.doesNotThrow(() => verifySignedMeaningManifest(badKey, manifest));
  assert.equal(verifySignedMeaningManifest(badKey, manifest).verified, false);

  const badSignature = clone(attestation);
  badSignature.signature_base64 = "%%%";
  assert.doesNotThrow(() => verifySignedMeaningManifest(badSignature, manifest));
  assert.equal(verifySignedMeaningManifest(badSignature, manifest).verified, false);
});

test("non-Ed25519 private keys are rejected", () => {
  const manifest = createMeaningManifest(sources);
  const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.throws(
    () => signMeaningManifest(manifest, privateKey.export({ type: "pkcs8", format: "pem" })),
    /requires an Ed25519 private key/
  );
});
