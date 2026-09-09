# ĀML Canonical JSON 1

Protocol: `aml-conformance/canonical-json-1`  
Status: experimental conformance level

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## Purpose

Hashes, signatures, receipts, witness bundles, manifests, and wire envelopes are only interoperable when independent implementations agree on the exact bytes being hashed or signed.

Canonical JSON 1 promotes the repository's existing `sorted-json-v1` vectors into an explicit cross-implementation conformance target.

## Normative input vectors

The normative vectors are:

```text
protocol/browser-canonicalization-vectors.json
```

The vector file identifies its canonicalization algorithm as `sorted-json-v1` and includes expected canonical strings plus SHA-256 digests.

## Required behavior

For the domain exercised by the published vectors, an implementation MUST:

1. preserve JSON array order;
2. sort object keys lexicographically at every nesting depth;
3. emit compact JSON with no insignificant whitespace;
4. preserve Unicode characters rather than ASCII-escaping them;
5. preserve JSON booleans and null values;
6. serialize the published safe integer values exactly;
7. produce the exact `canonical` UTF-8 string in each vector;
8. produce the exact lowercase SHA-256 digest of those UTF-8 bytes.

An implementation passes only when every canonical string and digest matches.

## Scope boundary

Canonical JSON 1 is not a complete general-purpose canonical JSON standard. In particular, this level does not define arbitrary floating-point normalization, duplicate-key handling before parsing, Unicode normalization forms, non-finite numbers, or values outside the JSON data model.

Those cases must not be inferred from this level. A future protocol revision may expand the domain explicitly.

## Independent reference checks

The repository includes an existing dependency-free Python checker:

```bash
python3 independent/python/check_canonical_vectors.py
```

It also includes a separate JavaScript checker under the conformance tree:

```bash
node conformance/independent-javascript/verify_canonical_json.mjs
```

Neither checker needs the ĀML runtime to reproduce the published canonicalization vectors.

## Why this level matters

Decision agreement tells two systems *what* happened. Canonical byte agreement lets them agree on the exact material used to prove what happened.

That is a prerequisite for portable cryptographic evidence across implementations.
