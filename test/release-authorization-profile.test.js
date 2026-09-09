import test from "node:test";
import assert from "node:assert/strict";

import {
  AML_SEMANTIC_RELEASE_PREDICATE_V1
} from "../compiler/inTotoSemanticRelease.js";
import {
  RELEASE_AUTHORIZATION_PROFILE_PROTOCOL,
  validateReleaseAuthorizationProfile,
  releaseAuthorizationProfileFingerprint,
  resolveReleaseAuthorizationProfile
} from "../tooling/releaseAuthorizationProfile.js";

function profile() {
  return {
    protocol: RELEASE_AUTHORIZATION_PROFILE_PROTOCOL,
    profile_id: "production-release-v1",
    repository: "acme/app",
    signer_workflow: "acme/app/.github/workflows/release.yml",
    allow_self_hosted: false,
    predicate_type: AML_SEMANTIC_RELEASE_PREDICATE_V1,
    required_layers: {
      github_attestation: true,
      semantic_release_proof: true,
      release_key_trust: true,
      semantic_release_quorum: true
    },
    release_key_policy_sha256: "a".repeat(64),
    quorum_policy_sha256: "b".repeat(64)
  };
}

test("release authorization profile has one deterministic canonical fingerprint", () => {
  const left = profile();
  const right = {
    quorum_policy_sha256: left.quorum_policy_sha256,
    required_layers: { ...left.required_layers },
    protocol: left.protocol,
    repository: left.repository,
    allow_self_hosted: left.allow_self_hosted,
    predicate_type: left.predicate_type,
    profile_id: left.profile_id,
    release_key_policy_sha256: left.release_key_policy_sha256,
    signer_workflow: left.signer_workflow
  };
  assert.equal(releaseAuthorizationProfileFingerprint(left), releaseAuthorizationProfileFingerprint(right));
});

test("repository, workflow, self-hosted posture, required layers and policy hashes are profile-bound", () => {
  const base = profile();
  const original = releaseAuthorizationProfileFingerprint(base);
  const mutations = [
    p => { p.repository = "acme/other"; },
    p => { p.signer_workflow = "acme/app/.github/workflows/other.yml"; },
    p => { p.allow_self_hosted = true; },
    p => { p.required_layers.release_key_trust = false; p.release_key_policy_sha256 = null; },
    p => { p.required_layers.semantic_release_quorum = false; p.quorum_policy_sha256 = null; },
    p => { p.release_key_policy_sha256 = "c".repeat(64); },
    p => { p.quorum_policy_sha256 = "d".repeat(64); }
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(base);
    mutate(changed);
    assert.notEqual(releaseAuthorizationProfileFingerprint(changed), original);
  }
});

test("profile refuses disabling mandatory GitHub or semantic proof layers", () => {
  const first = profile();
  first.required_layers.github_attestation = false;
  assert.equal(validateReleaseAuthorizationProfile(first).reason, "mandatory_layers_disabled");
  const second = profile();
  second.required_layers.semantic_release_proof = false;
  assert.equal(validateReleaseAuthorizationProfile(second).reason, "mandatory_layers_disabled");
});

test("profile requires policy hashes exactly when their layers are required", () => {
  const missingTrust = profile();
  missingTrust.release_key_policy_sha256 = null;
  assert.equal(validateReleaseAuthorizationProfile(missingTrust).reason, "release_key_policy_hash_required");

  const missingQuorum = profile();
  missingQuorum.quorum_policy_sha256 = null;
  assert.equal(validateReleaseAuthorizationProfile(missingQuorum).reason, "quorum_policy_hash_required");

  const unexpected = profile();
  unexpected.required_layers.semantic_release_quorum = false;
  assert.equal(validateReleaseAuthorizationProfile(unexpected).reason, "unexpected_quorum_policy_hash");
});

test("profile pins the AML semantic-release predicate and rejects arbitrary predicate substitution", () => {
  const changed = profile();
  changed.predicate_type = "https://slsa.dev/provenance/v1";
  assert.equal(validateReleaseAuthorizationProfile(changed).reason, "invalid_predicate_type");
});

test("expected profile SHA fails closed when any authorization posture drifts", () => {
  const base = profile();
  const expected = releaseAuthorizationProfileFingerprint(base);
  assert.equal(resolveReleaseAuthorizationProfile(base, { expectedProfileSha256: expected }).valid, true);
  const changed = structuredClone(base);
  changed.allow_self_hosted = true;
  const result = resolveReleaseAuthorizationProfile(changed, { expectedProfileSha256: expected });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "authorization_profile_fingerprint_mismatch");
});
