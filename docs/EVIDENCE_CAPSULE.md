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

A separate project-authored Python verifier checks capsules on the JSON subset for which its serializer reproduces the exact capsule digests. It also checks the receipt hash, intent/output/decision bindings, audit chain, ledger, counts, and derived summary. For signed v1.1 receipts it verifies Ed25519 and requires a separately supplied trusted receipt-key fingerprint; install `cryptography>=42,<51`:

```bash
python3 independent/python/verify_evidence_capsule.py capsule.json
python3 independent/python/verify_evidence_capsule.py signed-capsule.json trusted-policy.json
```

Unsigned capsules need one argument. Signed v1.1 capsules require a second JSON file with `trusted_receipt_fingerprints` (an array of SHA-256 SPKI DER fingerprints) and optional `revoked_receipt_fingerprints`. The embedded key is not a trust source. Legacy v1.0 signatures are unsupported in Python because their signer and signed time were not bound. The two implementations and their mutation cases are exercised with `node scripts/check-evidence-capsule-python.mjs` on CI, which publishes a JSON result artifact. Signed receipts with small and large exponents, boundary integers, the maximum finite JavaScript number, array-index-like keys, UTF-16-ordered keys, and escaped lone surrogates are checked there. A locally assembled, JavaScript-valid signed ledger also checks that three charges totaling beyond the safe-integer boundary use binary64 arithmetic. Boolean and negative-zero balance mutations must fail, while a negative-zero sequence spelling that JavaScript accepts must verify. Changed numerical values, escaped duplicate keys, and non-finite numbers must fail. This is cross-runtime engineering evidence maintained by the project, not an independent external witness.

For a saved response from the locked HTTP deployment endpoint, the [HTTP exchange pilot](../pilots/enterprise-http-gate/README.md#recheck-a-real-http-exchange-with-python) additionally checks host-owned expected inputs, nonce, HTTP envelope and effective decision in Python while reusing this signed capsule verifier. The capsule alone does not make those request and response claims.

## Frozen v1 contract

The capsule has exactly six top-level keys: `protocol`, `canonicalization`, `claim_boundary`, `summary`, `receipt`, and `digests`. The digest material consists of the first five keys, serialized with `canonicalJSONStringify` from `protocol/canonicalJson.js`: ordinary JSON values, object keys sorted by JavaScript UTF-16 code-unit order before `JSON.stringify`, no whitespace, JSON string escaping, and JSON number serialization. JavaScript enumerates array-index keys numerically ahead of other keys during that final serialization. The receipt's internal hashes use a separate, hand-built sorted JSON rule that keeps those keys in UTF-16 lexical order. The Python verifier reproduces both byte orders without changing either frozen JavaScript hash. `undefined`, non-finite numbers, executable values, and non-plain objects are rejected. Hash the capsule payload's UTF-8 bytes with SHA-256 and SHA-512 as lowercase hexadecimal.

The receipt's own v1.1 verification remains a separate contract. Both digest algorithms are required in this capsule version. New algorithms and formats should get a new version and test vectors; do not reinterpret old bytes. Do not overwrite an old capsule when migrating: retain it and record a new, separately verifiable link to its exact digest. The [renewal chain](EVIDENCE_RENEWAL.md) implements one such link with a verifier-owned trust policy. No verifier here establishes an external timestamp or independent validation. The Python implementation handles tested finite fractions, large integers and exponents through JavaScript's maximum finite number, rendering shortest round-trip digits at JavaScript's fixed/exponent boundary. JSON integer tokens above the safe-integer limit are rounded to binary64 before verification, as in JavaScript: distinct decimal spellings can denote the same signed Number. Attention-ledger arithmetic rounds after each binary64 operation; its before, after, and remaining balances use JavaScript `Object.is` semantics, including the sign of zero. Represent precision-critical identifiers and amounts as strings with a separate validation rule. Non-finite numbers are rejected. The verifier also reproduces tested UTF-16 key order, array-index enumeration, and JSON escaping of lone surrogates. This is a tested interoperability subset, not a proof of parity for every JavaScript number or arbitrary source string. Supplied JSON with duplicate keys is rejected before verification.

## Why preserve both views?

The `summary` is convenient to read but is derived from the bound receipt. Verification recalculates it. The receipt contains the full declared intent, context, policy decisions, output, and audit data needed to inspect what this implementation did. Reproducing the decision under another implementation additionally requires the original policy/compiler code and dependencies, which this capsule does not bundle.

See the [enterprise pilot](../pilots/enterprise-30min/README.md) for project-authored replay and mutation evidence, and the [evidence levels](../EVIDENCE.md) for the boundary between internal checks and external validation.
