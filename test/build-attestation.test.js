import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { compileAML, signBuildManifest, verifyBuildAttestation } from "../index.js";

test("AML build manifests can be signed and independently verified", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-attest-"));
  const sourcePath = path.join(dir, "source.aml");
  const outDir = path.join(dir, "dist");
  fs.writeFileSync(sourcePath, `transmission "signed" {\n  engram Card {\n    purpose: "Signed build test."\n    attention_cost: 1\n    restoration_value: 2\n  }\n}\n`);
  compileAML(sourcePath, outDir, { timestamp: "1970-01-01T00:00:00.000Z" });

  const { privateKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });

  const manifestPath = path.join(outDir, "build_manifest.json");
  const attestation = signBuildManifest(manifestPath, privateKey, {
    timestamp: "1970-01-01T00:00:00.000Z",
    signer: "test-suite"
  });
  const verification = verifyBuildAttestation(attestation, manifestPath);
  assert.equal(verification.verified, true);
  assert.equal(verification.signer, "test-suite");
});

test("attestation verification fails after manifest mutation", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-attest-tamper-"));
  const manifestPath = path.join(dir, "build_manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify({ ok: true }));
  const { privateKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const attestation = signBuildManifest(manifestPath, privateKey, { timestamp: "1970-01-01T00:00:00.000Z" });
  fs.appendFileSync(manifestPath, " ");
  const verification = verifyBuildAttestation(attestation, manifestPath);
  assert.equal(verification.verified, false);
  assert.equal(verification.signature_valid, false);
});
