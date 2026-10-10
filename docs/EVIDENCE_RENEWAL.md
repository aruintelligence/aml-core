# Evidence renewal for ĀML capsules

An evidence capsule preserves one decision. A renewal record adds an **append-only link** from that capsule's SHA-512 digest to a SHA3-512 digest of the entire capsule. Each record names its predecessor root and advances by exactly one sequence. Ed25519 attestations bind a witness's claimed name and time to that record. Verification requires a **verifier-supplied** trust policy and a quorum of distinct, non-revoked public-key fingerprints.

This is a versioned prototype mechanism for **algorithm diversity and continuity**, not a 5,000-year cryptographic promise. SHA3-512 and Ed25519 can also age. A later algorithm needs a new protocol version and an explicit migration that keeps the old bytes. The witness signers used by tests are generated in CI and are not external parties.

```js
import { createEvidenceRenewal, attestEvidenceRenewal, verifyEvidenceRenewalChain } from "aml-core";

const first = createEvidenceRenewal(capsule, { sequence: 1 });
const attestationA = attestEvidenceRenewal(first, witnessPrivateKeyPemA, { signer: "witness-a" });
const attestationB = attestEvidenceRenewal(first, witnessPrivateKeyPemB, { signer: "witness-b" });
const entries = [{ record: first, witnesses: [attestationA, attestationB] }];

const result = verifyEvidenceRenewalChain(capsule, entries, {
  threshold: 2,
  trusted_fingerprints: [trustedFingerprintA, trustedFingerprintB]
});
```

The two trusted fingerprints must come from a channel the verifier actually trusts. An embedded public key or a signer label is not enough. A threshold of two counts **distinct keys**, not two copies of one attestation. Revoked keys can be listed in `revoked_fingerprints`. To rotate trust, provide `trusted_fingerprints_by_sequence` with explicit allowed keys for each sequence; overlap old and new sets during a controlled transition.

For the next record, use `sequence: 2` and `previous_root_sha3_512: first.root_sha3_512`. Keep every earlier record and the exact original capsule. The verifier rejects gaps, changed predecessors, altered content, invalid signatures, missing quorum, and a chain that conflicts with `accepted_head: { sequence, root_sha3_512 }` supplied from a separately persisted trusted state. Without an accepted head, it checks internal continuity but **cannot know** whether someone withheld later records or replayed an old, otherwise valid chain. Even with a remembered head, it does not establish that the chain is the latest globally published state.

The `created_at` and `signed_at` fields are signed claims, not timestamps from an independent authority. Trust policy, key custody, revocation distribution, durable head storage, public transparency, and real external witnesses are deployment responsibilities. Passing repository tests is project-authored engineering evidence only.

See [evidence capsules](EVIDENCE_CAPSULE.md) for the underlying receipt format and [checkpoint witness boundaries](CHECKPOINT_WITNESS.md) for the separate release-trust control plane.
