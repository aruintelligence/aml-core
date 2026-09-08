import test from "node:test";
import assert from "node:assert/strict";
import {
  negotiateCapabilities,
  createPolicyPassport,
  verifyPolicyPassport,
  passportContext,
  createContentAddressedBundle,
  verifyContentAddressedBundle,
  createDisclosureCommitment,
  discloseClaims,
  verifyDisclosureProof,
  createWireEnvelope,
  validateWireEnvelope,
  negotiateWireSession
} from "../index.js";

test("capability negotiation selects common version and required capabilities", () => {
  const result = negotiateCapabilities(
    { versions: ["1.0", "1.1"], capabilities: ["receipts", "policy-passports", "view-meaning"] },
    { versions: ["1.1"], capabilities: ["receipts", "policy-passports"] },
    { required: ["receipts"] }
  );
  assert.equal(result.compatible, true);
  assert.equal(result.selected_version, "1.1");
  assert.deepEqual(result.common_capabilities, ["policy-passports", "receipts"]);
});

test("capability negotiation refuses missing required feature", () => {
  const result = negotiateCapabilities(
    { versions: ["1.0"], capabilities: ["receipts"] },
    { versions: ["1.0"], capabilities: [] },
    { required: ["receipts"] }
  );
  assert.equal(result.compatible, false);
  assert.deepEqual(result.missing_required, ["receipts"]);
});

test("policy passports verify, expire, and expose runtime context", () => {
  const passport = createPolicyPassport({
    subject: "user:example",
    profile: "human_first",
    preferences: { reduced_motion: true, privacy: "strict" },
    expires_at: "2030-01-01T00:00:00.000Z"
  });
  assert.equal(verifyPolicyPassport(passport, { now: "2029-01-01T00:00:00.000Z" }).valid, true);
  assert.equal(verifyPolicyPassport(passport, { now: "2031-01-01T00:00:00.000Z" }).reason, "expired");
  assert.equal(passportContext(passport).policy_profile, "human_first");

  const tampered = structuredClone(passport);
  tampered.preferences.privacy = "off";
  assert.equal(verifyPolicyPassport(tampered).reason, "hash_mismatch");
});

test("content-addressed bundles detect mutation", () => {
  const bundle = createContentAddressedBundle({
    "intent.json": { purpose: "Explain pricing" },
    "decision.json": { render_allowed: true }
  });
  assert.equal(verifyContentAddressedBundle(bundle).valid, true);
  const tampered = structuredClone(bundle);
  tampered.files["decision.json"].value.render_allowed = false;
  assert.equal(verifyContentAddressedBundle(tampered).reason, "entry_hash_mismatch");
});

test("selective disclosure proves disclosed claims while hiding others", () => {
  const commitment = createDisclosureCommitment({
    accessibility: "reduced-motion",
    privacy: "strict",
    age: "adult"
  });
  const proof = discloseClaims(commitment, ["accessibility"]);
  assert.equal(proof.disclosed.length, 1);
  assert.equal(proof.hidden.length, 2);
  assert.equal(verifyDisclosureProof(proof).valid, true);

  const tampered = structuredClone(proof);
  tampered.disclosed[0].value = "none";
  assert.equal(verifyDisclosureProof(tampered).valid, false);
});

test("wire envelopes validate and sessions negotiate explicitly", () => {
  const envelope = createWireEnvelope({
    kind: "execution-receipt",
    version: "1.0",
    capabilities: ["receipts", "policy-passports"],
    payload: { receipt_hash: "abc" }
  });
  assert.equal(validateWireEnvelope(envelope, { allowedKinds: ["execution-receipt"] }).valid, true);
  assert.equal(validateWireEnvelope(envelope, { allowedKinds: ["policy-pack"] }).reason, "unsupported_kind");

  const session = negotiateWireSession(
    { versions: ["1.0", "1.1"], capabilities: ["receipts", "selective-disclosure"] },
    { versions: ["1.1"], capabilities: ["receipts", "selective-disclosure", "audit"] },
    ["receipts"]
  );
  assert.equal(session.accepted, true);
  assert.equal(session.version, "1.1");
});
