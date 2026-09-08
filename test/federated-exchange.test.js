import test from "node:test";
import assert from "node:assert/strict";
import { createFederatedExchange, createPolicyPassport, verifyContentAddressedBundle, validateWireEnvelope } from "../index.js";

const local = {
  versions: ["1.0", "1.1"],
  capabilities: ["receipts", "policy-passports", "selective-disclosure", "content-addressed-bundles"]
};

const remote = {
  versions: ["1.1"],
  capabilities: ["receipts", "policy-passports", "content-addressed-bundles"]
};

test("federated exchange negotiates, verifies passport, binds artifacts, and emits wire envelope", () => {
  const passport = createPolicyPassport({
    subject: "user:example",
    profile: "human_first",
    preferences: { reduced_motion: true }
  });

  const exchange = createFederatedExchange({
    local,
    remote,
    required: ["receipts", "policy-passports"],
    passport,
    artifacts: {
      "intent.json": { purpose: "Explain account status" },
      "receipt.json": { render_allowed: true }
    }
  });

  assert.equal(exchange.accepted, true);
  assert.equal(exchange.negotiation.selected_version, "1.1");
  assert.equal(verifyContentAddressedBundle(exchange.bundle).valid, true);
  assert.equal(validateWireEnvelope(exchange.envelope).valid, true);
  assert.equal(exchange.envelope.payload.policy_passport_hash, passport.passport_hash);
  assert.equal(exchange.envelope.payload.bundle_root, exchange.bundle.root);
});

test("federated exchange refuses incompatible peer before artifact exchange", () => {
  const passport = createPolicyPassport({ profile: "human_first" });
  const exchange = createFederatedExchange({
    local,
    remote: { versions: ["1.1"], capabilities: ["receipts"] },
    required: ["policy-passports"],
    passport,
    artifacts: { "receipt.json": { render_allowed: true } }
  });

  assert.equal(exchange.accepted, false);
  assert.equal(exchange.reason, "capability_negotiation_failed");
  assert.equal(exchange.bundle, undefined);
});

test("federated exchange refuses tampered policy passport", () => {
  const passport = createPolicyPassport({ profile: "human_first", preferences: { privacy: "strict" } });
  passport.preferences.privacy = "off";
  const exchange = createFederatedExchange({
    local,
    remote,
    required: ["receipts"],
    passport,
    artifacts: {}
  });

  assert.equal(exchange.accepted, false);
  assert.equal(exchange.reason, "policy_passport_invalid");
});
