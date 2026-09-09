# ĀML Semantic Release Quorum

**Status: preview implementation — threshold authorization over verified Semantic Release Proofs**

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## Why this exists

A single cryptographically trusted release key is still a single point of compromise. ĀML Semantic Release Quorum lets a verifier require **M-of-N independently trusted Ed25519 endorsers** before accepting one exact semantic release.

The protocols are:

```text
aml-semantic-release-endorsement/1
aml-semantic-release-quorum-policy/1
```

A release endorsement binds all of the following before it is signed:

- Semantic Release Proof SHA-256;
- release ID;
- resulting Meaning Manifest root;
- Meaning Lineage head;
- endorser label;
- endorsement timestamp;
- endorser public-key fingerprint.

Changing the proof, semantic state, lineage, attribution, timestamp, or key invalidates the endorsement.

## Example 2-of-3 policy

```json
{
  "protocol": "aml-semantic-release-quorum-policy/1",
  "policy_id": "production-release-board",
  "threshold": 2,
  "trusted_keys": [
    { "public_key_sha256": "<key A sha256>", "signer": "security" },
    { "public_key_sha256": "<key B sha256>", "signer": "release" },
    { "public_key_sha256": "<key C sha256>", "signer": "product" }
  ]
}
```

Two distinct trusted fingerprints must produce valid endorsements. Two signatures from the same key count once. A valid signature from an unlisted key counts zero. A trusted key with the wrong configured signer label counts zero.

## Create an endorsement

```bash
aml-release-quorum endorse release-proof.json security-private-key.pem \
  --signer security > security.endorsement.json
```

Repeat independently for each endorser. The recommended operating model keeps private keys separated rather than placing all quorum keys in one workflow or secret store.

## Verify a quorum

Store endorsements as a JSON array:

```json
[
  { "protocol": "aml-semantic-release-endorsement/1", "...": "..." },
  { "protocol": "aml-semantic-release-endorsement/1", "...": "..." }
]
```

Then verify:

```bash
aml-release-quorum verify release-proof.json endorsements.json quorum-policy.json
```

For stronger policy-channel integrity, pin the canonical policy fingerprint:

```bash
POLICY_SHA=$(aml-release-quorum hash-policy quorum-policy.json)

aml-release-quorum verify release-proof.json endorsements.json quorum-policy.json \
  --policy-sha256 "$POLICY_SHA"
```

The policy hash is computed over strict canonical JSON material containing the protocol, policy ID, threshold, and trusted key constraints. A threshold or trusted-key change therefore changes the policy hash.

## Security properties

Verification fails closed when:

- the underlying Semantic Release Proof is invalid;
- the quorum policy is malformed;
- the threshold is less than 1 or greater than the trusted-key count;
- trusted fingerprints are duplicated;
- an endorsement targets another proof, release ID, meaning root, or lineage head;
- endorsement hash, public-key fingerprint, or signature fails;
- an endorsement key is not trusted;
- a signer constraint does not match;
- the same trusted key is presented repeatedly to inflate the count;
- the required threshold is not met;
- an expected quorum-policy SHA-256 does not match the policy supplied to the verifier.

## What this changes

The authorization ladder can now be:

```text
valid semantic proof
  → trusted release key
  → trusted GitHub/Sigstore workflow
  → exact proof-file bytes
  → M-of-N independently trusted release endorsements
```

A deployment can choose how far up that ladder it needs to go.

## Evidence boundary

Quorum verification establishes only that the configured threshold of verifier-selected keys signed the exact release evidence. It does not establish objective truth, safety, ethics, legal compliance, certification, institutional authority, or standards approval.

It also does not help if all quorum private keys are controlled by the same compromised system. Independence is an operational property: separate custody, separate identities, separate approval paths, hardware-backed keys, or organizational separation can strengthen the real-world meaning of a threshold.

ĀML supplies the cryptographic enforcement primitive. The verifier remains responsible for deciding which keys deserve trust and how those keys are governed.
