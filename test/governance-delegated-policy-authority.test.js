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
import { createSignedTrustDelegation } from "../runtime/trustDelegation.js";

function keypair() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString()
  };
}

function fingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

function preparedAuthorization(session, update, signer, delegationChain) {
  const transition = createGovernancePolicyTransition({
    transmission: session.transmission,
    expected_policy_epoch: session.policy_epoch,
    previous_policy_sha256: session.policy_sha256,
    update
  });
  const signature = signGovernancePolicyTransition(transition, signer.privateKeyPem, {
    signer: "delegated-operator",
    delegation_chain: delegationChain
  });
  return createGovernancePolicyTransitionAuthorization(transition, [signature]);
}

test("trusted root can delegate live policy authority without directly trusting leaf key", () => {
  const root = keypair();
  const leaf = keypair();
  const delegation = createSignedTrustDelegation({
    issuer: "governance-root",
    delegate: "deployment-operator",
    delegate_public_key_pem: leaf.publicKeyPem,
    capabilities: ["governance-policy-transition"],
    issued_at: "2026-09-10T00:00:00.000Z",
    expires_at: "2027-09-10T00:00:00.000Z"
  }, root.privateKeyPem);

  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "delegated-stream" });
  const authorization = preparedAuthorization(probe, { mode: "shadow" }, leaf, [delegation]);
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "delegated-stream",
    policy_authorization: {
      required: true,
      threshold: 1,
      trusted_fingerprints: [fingerprint(root.publicKeyPem)],
      allow_delegated_authority: true,
      now: "2026-09-10T12:00:00.000Z"
    }
  });

  const result = session.accept({
    protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE,
    mode: "shadow",
    authorization
  });
  assert.equal(result.authorization.authorized, true);
  assert.equal(session.mode, "shadow");
});

test("multi-hop delegation preserves key continuity and capability scope", () => {
  const root = keypair();
  const intermediate = keypair();
  const leaf = keypair();
  const rootToIntermediate = createSignedTrustDelegation({
    issuer: "governance-root",
    delegate: "regional-authority",
    delegate_public_key_pem: intermediate.publicKeyPem,
    capabilities: ["governance-policy-transition"]
  }, root.privateKeyPem);
  const intermediateToLeaf = createSignedTrustDelegation({
    issuer: "regional-authority",
    delegate: "deployment-operator",
    delegate_public_key_pem: leaf.publicKeyPem,
    capabilities: ["governance-policy-transition"]
  }, intermediate.privateKeyPem);

  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "multihop-stream" });
  const authorization = preparedAuthorization(probe, { failure_mode: "open" }, leaf, [rootToIntermediate, intermediateToLeaf]);
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "multihop-stream",
    policy_authorization: {
      required: true,
      threshold: 1,
      trusted_fingerprints: [fingerprint(root.publicKeyPem)],
      allow_delegated_authority: true
    }
  });

  session.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, failure_mode: "open", authorization });
  assert.equal(session.failure_mode, "open");
});

test("delegation without required capability is rejected before state mutation", () => {
  const root = keypair();
  const leaf = keypair();
  const delegation = createSignedTrustDelegation({
    issuer: "governance-root",
    delegate: "read-only-operator",
    delegate_public_key_pem: leaf.publicKeyPem,
    capabilities: ["governance-observe"]
  }, root.privateKeyPem);
  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "scope-stream" });
  const authorization = preparedAuthorization(probe, { mode: "shadow" }, leaf, [delegation]);
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "scope-stream",
    policy_authorization: {
      required: true,
      threshold: 1,
      trusted_fingerprints: [fingerprint(root.publicKeyPem)],
      allow_delegated_authority: true
    }
  });

  assert.throws(() => session.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, mode: "shadow", authorization }), /AML_POLICY_TRANSITION_UNAUTHORIZED/);
  assert.equal(session.mode, "enforce");
});

test("revoked delegated leaf cannot exercise authority", () => {
  const root = keypair();
  const leaf = keypair();
  const delegation = createSignedTrustDelegation({
    issuer: "governance-root",
    delegate: "deployment-operator",
    delegate_public_key_pem: leaf.publicKeyPem,
    capabilities: ["governance-policy-transition"]
  }, root.privateKeyPem);
  const leafFingerprint = fingerprint(leaf.publicKeyPem);
  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "revoked-stream" });
  const authorization = preparedAuthorization(probe, { mode: "shadow" }, leaf, [delegation]);
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "revoked-stream",
    policy_authorization: {
      required: true,
      threshold: 1,
      trusted_fingerprints: [fingerprint(root.publicKeyPem)],
      revoked_fingerprints: [leafFingerprint],
      allow_delegated_authority: true
    }
  });

  assert.throws(() => session.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, mode: "shadow", authorization }), /AML_POLICY_TRANSITION_UNAUTHORIZED/);
  assert.equal(session.policy_epoch, 0);
});

test("delegated authority must be explicitly enabled by verifier policy", () => {
  const root = keypair();
  const leaf = keypair();
  const delegation = createSignedTrustDelegation({
    issuer: "governance-root",
    delegate: "deployment-operator",
    delegate_public_key_pem: leaf.publicKeyPem,
    capabilities: ["governance-policy-transition"]
  }, root.privateKeyPem);
  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "disabled-delegation-stream" });
  const authorization = preparedAuthorization(probe, { mode: "shadow" }, leaf, [delegation]);
  const session = createGovernanceStreamSession({
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission: "disabled-delegation-stream",
    policy_authorization: {
      required: true,
      threshold: 1,
      trusted_fingerprints: [fingerprint(root.publicKeyPem)]
    }
  });

  assert.throws(() => session.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, mode: "shadow", authorization }), /AML_POLICY_TRANSITION_UNAUTHORIZED/);
});
