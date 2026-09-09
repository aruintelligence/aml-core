# ĀML Release Authorization Profile

**Status: preview implementation — verifier-supplied immutable release authorization posture**

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## One policy object instead of a pile of trust flags

ĀML's release verification stack can independently require GitHub/Sigstore workflow identity, exact proof-file bytes, a verified Semantic Release Proof, an externally trusted semantic release key, and an M-of-N Semantic Release Quorum.

The Release Authorization Profile binds those choices into one canonical machine contract:

```text
aml-release-authorization-profile/1
```

Example:

```json
{
  "protocol": "aml-release-authorization-profile/1",
  "profile_id": "production-release-v1",
  "repository": "OWNER/REPOSITORY",
  "signer_workflow": "OWNER/REPOSITORY/.github/workflows/release.yml",
  "allow_self_hosted": false,
  "predicate_type": "https://aruintelligence.github.io/aml-core/predicates/semantic-release/v1.json",
  "required_layers": {
    "github_attestation": true,
    "semantic_release_proof": true,
    "release_key_trust": true,
    "semantic_release_quorum": true
  },
  "release_key_policy_sha256": "<canonical release-key policy SHA-256>",
  "quorum_policy_sha256": "<canonical quorum policy SHA-256>"
}
```

The GitHub attestation and Semantic Release Proof layers are mandatory in profile version 1. A profile cannot turn them off.

## Pin the complete authorization posture

```bash
aml-release-profile hash production-release-profile.json
```

A verifier can preserve that SHA-256 outside the release pipeline and later require the exact same profile:

```bash
aml-release-profile verify production-release-profile.json <expected-profile-sha256>
```

The fingerprint commits to:

- repository identity;
- optional signer workflow identity;
- whether self-hosted-runner attestations are allowed;
- the exact ĀML semantic-release predicate URI;
- which trust layers are mandatory;
- the canonical release-key trust-policy SHA-256 when release-key trust is required;
- the canonical quorum-policy SHA-256 when quorum is required.

Changing any of those changes the profile hash.

## Verify a release under one profile

When a profile is used, it supplies the authorization posture. Evidence files still supply the actual trust policies and endorsements whose hashes are pinned by the profile:

```bash
aml-github-attestation release-proof.json \
  --authorization-profile production-release-profile.json \
  --authorization-profile-sha256 <expected-profile-sha256> \
  --trust-policy release-key-policy.json \
  --quorum-policy quorum-policy.json \
  --quorum-endorsements endorsements.json
```

Profile mode rejects ad-hoc overrides for repository, signer workflow, self-hosted policy, release-key policy hash, or quorum policy hash. This prevents command-line policy from silently weakening a pinned profile.

If the profile requires release-key trust, a release-key policy evidence file is mandatory and must hash to the profile's pinned value. If the profile requires quorum, both the quorum policy and endorsement array are mandatory and the policy must hash to the profile's pinned value. Evidence for a layer the profile says is not required is rejected rather than silently accepted.

## Why the profile is external

The release being verified must not get to choose its own authorization profile. A compromised release pipeline that can replace both an artifact and the rules for trusting that artifact has circular authority.

The profile and, for stronger deployments, its expected SHA-256 should arrive through a verifier-controlled channel: configuration management, protected infrastructure, a hardware-backed policy store, a separately governed repository, or another out-of-band mechanism appropriate to the threat model.

## Security boundary

A valid profile hash proves that one policy object has not changed relative to the pinned hash. It does not prove that the policy is wise, that its keys are independently governed, that the named workflow is uncompromised, or that a release is safe, ethical, legal, true, certified, or standards-approved.

ĀML provides a machine-enforceable authorization contract. The verifier remains responsible for governing the trust roots named by that contract.
