import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  createGovernanceStreamSession,
  AML_GOVERNANCE_STREAM_OPEN,
  AML_GOVERNANCE_STREAM_POLICY_UPDATE
} from "../protocol/governanceStream.js";
import {
  createGovernancePolicyTransition,
  signGovernancePolicyTransition,
  createGovernancePolicyTransitionAuthorization
} from "../protocol/governancePolicyAuthorization.js";

function keypair() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

function signedTransition(session, update, privateKeys) {
  const transition = createGovernancePolicyTransition({
    transmission: session.transmission,
    expected_policy_epoch: session.policy_epoch,
    previous_policy_sha256: session.policy_sha256,
    update
  });
  const signatures = privateKeys.map((key, index) => signGovernancePolicyTransition(transition, key, { signer: `witness-${index + 1}` }));
  return { transition, authorization: createGovernancePolicyTransitionAuthorization(transition, signatures), fingerprints: signatures.map(s => s.public_key_fingerprint_sha256) };
}

test("two trusted witnesses can authorize a live policy transition", () => {
  const keys = [keypair(), keypair()];
  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "authorized-stream" });
  const prepared = signedTransition(probe, { mode: "shadow" }, keys);
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "authorized-stream",
    policy_authorization: { required: true, threshold: 2, trusted_fingerprints: prepared.fingerprints }
  });
  const result = session.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, mode: "shadow", authorization: prepared.authorization });
  assert.equal(result.authorization.authorized, true);
  assert.equal(result.authorization.eligible_signatures, 2);
  assert.equal(session.mode, "shadow");
  assert.equal(session.policy_epoch, 1);
});

test("missing authorization is rejected before state mutation", () => {
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "locked-stream",
    policy_authorization: { required: true, threshold: 1, trusted_fingerprints: [] }
  });
  assert.throws(() => session.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, mode: "shadow" }), /AML_POLICY_TRANSITION_AUTHORIZATION_REQUIRED/);
  assert.equal(session.mode, "enforce");
  assert.equal(session.policy_epoch, 0);
});

test("authorization for different update cannot be replayed onto new policy request", () => {
  const key = keypair();
  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "binding-stream" });
  const prepared = signedTransition(probe, { mode: "shadow" }, [key]);
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "binding-stream",
    policy_authorization: { required: true, threshold: 1, trusted_fingerprints: prepared.fingerprints }
  });
  assert.throws(() => session.accept({
    protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE,
    failure_mode: "open",
    authorization: prepared.authorization
  }), /AML_POLICY_TRANSITION_AUTHORIZATION_MISMATCH/);
  assert.equal(session.failure_mode, "closed");
});

test("duplicate signing key cannot satisfy a two-key threshold", () => {
  const key = keypair();
  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "duplicate-stream" });
  const transition = createGovernancePolicyTransition({
    transmission: probe.transmission,
    expected_policy_epoch: probe.policy_epoch,
    previous_policy_sha256: probe.policy_sha256,
    update: { mode: "shadow" }
  });
  const signature = signGovernancePolicyTransition(transition, key);
  const authorization = createGovernancePolicyTransitionAuthorization(transition, [signature, structuredClone(signature)]);
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "duplicate-stream",
    policy_authorization: { required: true, threshold: 2, trusted_fingerprints: [signature.public_key_fingerprint_sha256] }
  });
  assert.throws(() => session.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, mode: "shadow", authorization }), /AML_POLICY_TRANSITION_UNAUTHORIZED/);
});
