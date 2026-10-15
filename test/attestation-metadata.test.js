import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  executeAccountableIntent,
  signExecutionReceipt,
  verifySignedExecutionReceipt,
  normalizePolicyPack,
  signPolicyPack,
  verifySignedPolicyPack
} from "../index.js";

const timestamp = "2032-01-01T00:00:00.000Z";

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().filter(key => value[key] !== undefined).map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(typeof value === "string" || Buffer.isBuffer(value) ? value : stableStringify(value)).digest("hex");
}

function legacyObjectSha256(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : stableStringify(value)).digest("hex");
}

function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKey,
    publicKey,
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    fingerprint: sha256(publicDer),
    legacyFingerprint: legacyObjectSha256(publicDer)
  };
}

function receipt() {
  return executeAccountableIntent({
    transmission: "attestation_test",
    nodes: [{
      type: "engram",
      identifier: "notice",
      properties: {
        purpose: "Test signed attribution.",
        attention_cost: 1,
        restoration_value: 2
      }
    }]
  }, {
    timestamp,
    profile: "calm_default",
    context: {}
  });
}

function policyPack() {
  return {
    id: "attestation_test_pack",
    issuer: "original-policy-issuer",
    policies: ["restorative_v1"]
  };
}

test("current execution receipt attestation binds signer and signing time", () => {
  const keys = keyPair();
  const signed = signExecutionReceipt(receipt(), keys.privatePem, {
    signer: "original-signer",
    timestamp
  });

  assert.equal(signed.signature.public_key_sha256, keys.fingerprint);
  const verification = verifySignedExecutionReceipt(signed);
  assert.equal(verification.verified, true);
  assert.equal(verification.attribution_bound, true);
  assert.equal(verification.signer, "original-signer");
  assert.equal(verification.signed_at, timestamp);

  const signerTampered = structuredClone(signed);
  signerTampered.signature.signer = "forged-signer";
  assert.equal(verifySignedExecutionReceipt(signerTampered).verified, false);

  const timeTampered = structuredClone(signed);
  timeTampered.signature.signed_at = "2099-01-01T00:00:00.000Z";
  assert.equal(verifySignedExecutionReceipt(timeTampered).verified, false);
});

test("legacy execution receipt signatures verify payload but do not authenticate attribution", () => {
  const keys = keyPair();
  const unsigned = receipt();
  const legacySignature = crypto.sign(null, Buffer.from(unsigned.receipt_sha256, "utf8"), keys.privateKey);
  const legacy = {
    ...unsigned,
    signature: {
      protocol: "ĀML Execution Receipt Attestation",
      version: "1.0",
      algorithm: "Ed25519",
      signer: "legacy-claimed-signer",
      signed_at: timestamp,
      public_key_pem: keys.publicPem,
      public_key_sha256: keys.legacyFingerprint,
      signature_base64: legacySignature.toString("base64")
    }
  };

  const verification = verifySignedExecutionReceipt(legacy);
  assert.equal(verification.verified, true);
  assert.equal(verification.signature_valid, true);
  assert.equal(verification.public_key_fingerprint_valid, true);
  assert.equal(verification.attribution_bound, false);
  assert.equal(verification.signer, null);
  assert.equal(verification.signed_at, null);
  assert.equal(verification.claimed_signer, "legacy-claimed-signer");
  assert.equal(verification.claimed_signed_at, timestamp);

  legacy.signature.signer = "attacker-can-change-this-legacy-label";
  const relabeled = verifySignedExecutionReceipt(legacy);
  assert.equal(relabeled.verified, true);
  assert.equal(relabeled.attribution_bound, false);
  assert.equal(relabeled.signer, null);
  assert.equal(relabeled.claimed_signer, "attacker-can-change-this-legacy-label");
});

test("malformed execution receipt public key returns a clean verification failure", () => {
  const keys = keyPair();
  const signed = signExecutionReceipt(receipt(), keys.privatePem, { signer: "key-test", timestamp });
  signed.signature.public_key_pem = "not a public key";

  assert.doesNotThrow(() => verifySignedExecutionReceipt(signed));
  const verification = verifySignedExecutionReceipt(signed);
  assert.equal(verification.verified, false);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.public_key_fingerprint_valid, false);
});

test("execution receipt signer and verifier enforce the declared Ed25519 key type", () => {
  for (const [type, options] of [["rsa", { modulusLength: 2048 }], ["ec", { namedCurve: "prime256v1" }]]) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync(type, options);
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
    assert.throws(() => signExecutionReceipt(receipt(), privatePem), /requires an Ed25519 private key/);

    // A valid RSA/ECDSA signature can be mislabeled as Ed25519 because Node's
    // crypto.sign(null, ...) selects a default for those key types as well.
    const unsigned = receipt();
    const attestation = { protocol: "ĀML Execution Receipt Attestation", version: "1.1",
      algorithm: "Ed25519", signer: "synthetic", signed_at: timestamp,
      public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      public_key_sha256: sha256(publicKey.export({ type: "spki", format: "der" })) };
    const material = { protocol: attestation.protocol, version: attestation.version,
      algorithm: attestation.algorithm, receipt_sha256: unsigned.receipt_sha256,
      signer: attestation.signer, signed_at: attestation.signed_at };
    const bytes = Buffer.from(stableStringify(material));
    const raw = crypto.sign(null, bytes, privateKey);
    assert.equal(crypto.verify(null, bytes, publicKey, raw), true);
    const fabricated = { ...unsigned, signature: { ...attestation, signature_base64: raw.toString("base64") } };
    const result = verifySignedExecutionReceipt(fabricated);
    assert.equal(result.integrity_valid, true);
    assert.equal(result.verified, false);
    assert.equal(result.attribution_bound, false);
  }
});

test("execution receipt verifier rejects signature text that decodes to valid bytes noncanonically", () => {
  const signed = signExecutionReceipt(receipt(), keyPair().privatePem, { signer: "synthetic", timestamp });
  const original = signed.signature.signature_base64;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const alternate = original.slice(0, -3) + alphabet[alphabet.indexOf(original.at(-3)) + 1] + "==";
  for (const encoded of [original + "!!!!", original.slice(0, -2), alternate]) {
    assert.deepEqual(Buffer.from(encoded, "base64"), Buffer.from(original, "base64"));
    const mutated = structuredClone(signed);
    mutated.signature.signature_base64 = encoded;
    const result = verifySignedExecutionReceipt(mutated);
    assert.equal(result.integrity_valid, true);
    assert.equal(result.public_key_fingerprint_valid, true);
    assert.equal(result.signature_valid, false);
    assert.equal(result.verified, false);
  }
});

test("current policy pack attestation binds signer and signing time", () => {
  const keys = keyPair();
  const signed = signPolicyPack(policyPack(), keys.privatePem, {
    signer: "policy-signer",
    timestamp
  });

  assert.equal(signed.attestation.public_key_sha256, keys.fingerprint);
  const verification = verifySignedPolicyPack(signed);
  assert.equal(verification.verified, true);
  assert.equal(verification.attribution_bound, true);
  assert.equal(verification.signer, "policy-signer");
  assert.equal(verification.signed_at, timestamp);

  const signerTampered = structuredClone(signed);
  signerTampered.attestation.signer = "forged-policy-signer";
  assert.equal(verifySignedPolicyPack(signerTampered).verified, false);

  const timeTampered = structuredClone(signed);
  timeTampered.attestation.signed_at = "2099-01-01T00:00:00.000Z";
  assert.equal(verifySignedPolicyPack(timeTampered).verified, false);
});

test("legacy policy pack signatures verify payload but do not authenticate attribution", () => {
  const keys = keyPair();
  const normalized = normalizePolicyPack(policyPack());
  const payload = Buffer.from(stableStringify(normalized), "utf8");
  const legacySignature = crypto.sign(null, payload, keys.privateKey);
  const legacy = {
    ...normalized,
    pack_sha256: legacyObjectSha256(normalized),
    attestation: {
      algorithm: "Ed25519",
      signer: "legacy-policy-claim",
      signed_at: timestamp,
      public_key_sha256: keys.legacyFingerprint,
      public_key_pem: keys.publicPem,
      signature_base64: legacySignature.toString("base64")
    }
  };

  const verification = verifySignedPolicyPack(legacy);
  assert.equal(verification.verified, true);
  assert.equal(verification.signature_valid, true);
  assert.equal(verification.public_key_fingerprint_valid, true);
  assert.equal(verification.attribution_bound, false);
  assert.equal(verification.signer, null);
  assert.equal(verification.signed_at, null);
  assert.equal(verification.claimed_signer, "legacy-policy-claim");

  legacy.attestation.signer = "rewritten-legacy-policy-claim";
  const relabeled = verifySignedPolicyPack(legacy);
  assert.equal(relabeled.verified, true);
  assert.equal(relabeled.attribution_bound, false);
  assert.equal(relabeled.signer, null);
});

test("policy pack verification rejects top-level version tampering instead of normalizing it away", () => {
  const keys = keyPair();
  const signed = signPolicyPack(policyPack(), keys.privatePem, { signer: "policy-signer", timestamp });
  signed.version = "999.0";

  const verification = verifySignedPolicyPack(signed);
  assert.equal(verification.verified, false);
  assert.equal(verification.reason, "unsupported policy pack version");
});

test("malformed policy pack public key returns a clean verification failure", () => {
  const keys = keyPair();
  const signed = signPolicyPack(policyPack(), keys.privatePem, { signer: "policy-signer", timestamp });
  signed.attestation.public_key_pem = "not a public key";

  assert.doesNotThrow(() => verifySignedPolicyPack(signed));
  const verification = verifySignedPolicyPack(signed);
  assert.equal(verification.verified, false);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.public_key_fingerprint_valid, false);
});
