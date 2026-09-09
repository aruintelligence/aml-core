# ĀML External Release-Key Trust

**Status: preview implementation; verifier-supplied trust policy, not a certification system**

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## The problem

A cryptographically valid `aml-semantic-release-proof/1` establishes that the proof was signed by the private key corresponding to its embedded public key fingerprint. That is key possession and artifact integrity. It is not, by itself, evidence that the key was authorized to sign releases for a particular organization or deployment.

The experimental external policy protocol is:

```text
aml-release-key-trust-policy/1
```

Canonical policy-fingerprint material is domain-separated as:

```text
aml-release-key-trust-policy-material/1
```

A verifier can supply a policy such as:

```json
{
  "protocol": "aml-release-key-trust-policy/1",
  "policy_id": "production-release-keys",
  "trusted_keys": [
    {
      "public_key_sha256": "<approved lowercase SHA-256 fingerprint>",
      "signer": "release-bot"
    }
  ]
}
```

`trusted_keys` is an explicit allow-list. The fingerprint must be lowercase 64-character SHA-256 hex. Fingerprints must be unique. `signer` may be a string constraint or `null`/omitted to trust the fingerprint regardless of the signed human-readable signer label.

## Pin the policy itself

A trusted-key file can also be replaced. To make that replacement detectable, ĀML computes a deterministic SHA-256 over domain-separated canonical policy material. Trusted-key entries are sorted by fingerprint and signer before canonicalization, so array ordering does not change the policy identity, while changes to the policy ID, key fingerprints, or signer constraints do.

Compute the fingerprint:

```bash
aml-release-proof policy-hash release-key-policy.json
```

Then require that exact policy identity during standalone verification:

```bash
aml-release-proof trusted \
  release-proof.json \
  release-key-policy.json \
  <expected-policy-sha256>
```

Or require the same pin across GitHub/Sigstore + ĀML verification:

```bash
aml-github-attestation release-proof.json \
  --repo OWNER/REPOSITORY \
  --trust-policy release-key-policy.json \
  --trust-policy-sha256 <expected-policy-sha256>
```

The expected policy hash must itself come from an independently trusted channel. If an attacker can replace both `release-key-policy.json` and the expected hash in the same compromised location, the hash adds integrity comparison but not an independent trust anchor.

## Standalone verification

Without a separate policy-hash pin:

```bash
aml-release-proof trusted release-proof.json release-key-policy.json
```

Verification succeeds only when:

1. the complete Semantic Release Proof verifies;
2. the trust-policy structure is valid;
3. when supplied, the expected policy SHA-256 matches the canonical policy fingerprint;
4. the proof's public-key fingerprint appears in the external policy;
5. any signer-label constraint also matches the signer authenticated by the proof signature.

## GitHub/Sigstore + ĀML + release-key trust

```bash
aml-github-attestation release-proof.json \
  --repo OWNER/REPOSITORY \
  --trust-policy release-key-policy.json
```

This combines three independent checks:

1. GitHub/Sigstore workflow attestation and exact proof-file byte binding;
2. ĀML semantic release proof integrity and reproducibility;
3. verifier-selected release-key trust, optionally bound to an exact canonical policy fingerprint.

A valid GitHub attestation cannot substitute for the release-key policy. A valid release-key policy cannot substitute for the GitHub workflow attestation. A valid Semantic Release Proof cannot substitute for either external trust layer.

## Why the policy is external

The policy is intentionally not embedded as a self-authorizing field in the Semantic Release Proof. If the object being verified could declare its own trusted key, an attacker could replace the key, regenerate the proof, and declare the new key trusted in the same artifact.

The policy must therefore arrive through a channel the verifier chooses to trust: for example a locally pinned configuration, deployment control plane, separately authenticated configuration repository, hardware-backed policy distribution, or another independently governed trust source. The optional expected policy hash should be distributed through the same or stronger independent trust channel.

This implementation validates policy structure, deterministic policy identity, and matching semantics. It does not claim to authenticate the provenance of the policy file or expected hash by itself.

## Evidence boundary

A successful trusted verification establishes that:

- the Semantic Release Proof is cryptographically valid under its declared ĀML contracts;
- its signing-key fingerprint is authorized **relative to the verifier-supplied trust policy**, optionally under a signer-label constraint; and
- when an expected policy fingerprint is supplied, the policy semantics match that exact externally expected fingerprint.

It does not establish universal or institutional authority, standards certification, objective truth of declared meaning, safety, ethics, legal compliance, or SLSA compliance. Authorization exists only relative to the external policy and the trust placed in the channel that supplied that policy and any expected policy fingerprint.
