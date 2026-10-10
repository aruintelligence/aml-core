# ĀML evidence capsule

A capsule is a self-contained JSON preservation package for one accountable execution receipt. It carries the original receipt, a short derived decision summary, the verification contract identifier, and SHA-256 plus SHA-512 digests over the same canonical payload. It is meant to be readable and rechecked after the original interface has changed or disappeared.

This is an **integrity and preservation format**, not a claim that a decision was correct, that declared attention values measure a person, or that the capsule will remain secure for any particular period. Anyone can calculate fresh unsalted digests. A signed receipt retains its signature, but the embedded public key is not itself an independently trusted identity. Preserve external trust anchors, source and policy versions, and independent witness records separately when those claims matter.

## Use it

From the repository root, create a receipt with `executeAccountableIntent`, then:

```bash
node scripts/evidence-capsule.mjs create receipt.json > capsule.json
node scripts/evidence-capsule.mjs verify capsule.json
```

Verification returns `verified: true` and exits 0 only when both capsule digests, the receipt's internal bindings, a present Ed25519 signature, and the derived summary all validate. A failed verification exits 1. An unsupported protocol, canonicalization, field, or malformed value fails closed.

A separate project-authored Python verifier checks **unsigned capsules** on the JSON subset for which its serializer reproduces the exact capsule digests. It also checks the receipt hash, intent/output/decision bindings, audit chain, ledger, counts, and derived summary:

```bash
python3 independent/python/verify_evidence_capsule.py capsule.json
```

It rejects signed capsules until trusted-key signature verification is implemented in that runtime. The two implementations and their mutation cases are exercised with `node scripts/check-evidence-capsule-python.mjs` on CI. This is cross-runtime engineering evidence maintained by the project, not an independent external witness.

## Frozen v1 contract

The capsule has exactly six top-level keys: `protocol`, `canonicalization`, `claim_boundary`, `summary`, `receipt`, and `digests`. The digest material consists of the first five keys, serialized with `canonicalJSONStringify` from `protocol/canonicalJson.js`: ordinary JSON values, object keys sorted by JavaScript UTF-16 code-unit order, no whitespace, JSON string escaping, and JSON number serialization. `undefined`, non-finite numbers, executable values, and non-plain objects are rejected. Hash the resulting UTF-8 bytes with SHA-256 and SHA-512 as lowercase hexadecimal.

The receipt's own v1.1 verification remains a separate contract. Both digest algorithms are required in this capsule version. New algorithms and formats should get a new version and test vectors; do not reinterpret old bytes. Do not overwrite an old capsule when migrating: retain it and record a new, separately verifiable link to its exact digest. The current verifier does not establish an external timestamp or cross-language conformance, and JSON parsers that accept duplicate keys should reject such input before parsing if the original bytes are supplied by an adversary.

## Why preserve both views?

The `summary` is convenient to read but is derived from the bound receipt. Verification recalculates it. The receipt contains the full declared intent, context, policy decisions, output, and audit data needed to inspect what this implementation did. Reproducing the decision under another implementation additionally requires the original policy/compiler code and dependencies, which this capsule does not bundle.

See the [enterprise pilot](../pilots/enterprise-30min/README.md) for project-authored replay and mutation evidence, and the [evidence levels](../EVIDENCE.md) for the boundary between internal checks and external validation.
