# ĀML Sorted JSON 1

Protocol: `aml-conformance/sorted-json-1`  
Status: experimental conformance level

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## Purpose

Hashes, signatures, receipts, witness bundles, manifests, and wire envelopes are only interoperable when independent implementations agree on the exact bytes being hashed or signed.

Sorted JSON 1 promotes the repository's existing `sorted-json-v1` vectors into an explicit cross-implementation target without claiming to define a complete general-purpose JSON canonicalization standard.

## Normative input vectors

The normative vectors are:

```text
protocol/browser-canonicalization-vectors.json
```

The vector file identifies its algorithm as `sorted-json-v1` and includes expected serialized strings plus SHA-256 digests.

## Required behavior

For the domain exercised by the published vectors, an implementation MUST:

1. preserve JSON array order;
2. sort object keys lexicographically at every nesting depth;
3. emit compact JSON with no insignificant whitespace;
4. preserve Unicode characters rather than ASCII-escaping them;
5. preserve JSON booleans and null values;
6. serialize the published safe integer values exactly;
7. produce the exact expected UTF-8 string in each vector;
8. produce the exact lowercase SHA-256 digest of those UTF-8 bytes.

An implementation passes only when every expected string and digest matches.

## Scope boundary

Sorted JSON 1 is deliberately narrower than a general canonical-JSON specification. It does not define arbitrary floating-point normalization, duplicate-key handling before parsing, Unicode normalization forms, non-finite numbers, or values outside the published vector domain.

No implementer should infer behavior for those cases from this protocol. Expanding the accepted input domain requires a new versioned protocol unless the expansion is provably backward-compatible and explicitly specified.

The name **Sorted JSON 1** is intentional. It avoids implying equivalence with other JSON canonicalization specifications or standards.

## Independent checks

The repository includes independent checks that do not import the ĀML runtime:

```bash
python3 independent/python/check_canonical_vectors.py
node conformance/independent-javascript/verify_canonical_json.mjs
```

## Why this level matters

Decision agreement tells two systems *what* happened. Byte agreement lets them agree on the exact material used to prove what happened.

That is a prerequisite for portable cryptographic evidence across implementations.
