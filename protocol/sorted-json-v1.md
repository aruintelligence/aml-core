# sorted-json-v1

**Status: SHIPPED prototype canonicalization profile**

`sorted-json-v1` is the current canonical JSON byte rule used by the browser evidence and witness-bundle prototype.

## Rule

1. Recursively sort object keys by Unicode code-unit order as produced by JavaScript `Object.keys(value).sort()`.
2. Preserve array order exactly.
3. Omit object properties whose JavaScript value is `undefined` before serialization.
4. Serialize the resulting JSON-compatible value with compact JSON equivalent to JavaScript `JSON.stringify`.
5. Encode the resulting string as UTF-8 before hashing or signing.

## Cross-language safe domain

The published golden vectors currently cover:

- objects;
- arrays;
- strings including Unicode;
- booleans;
- null;
- integers within JavaScript's safe integer range.

The current profile does **not** claim fully specified cross-language behavior for every IEEE-754 edge case, including non-integer numeric formatting, `-0`, NaN, Infinity, or values outside JSON's data model.

Implementations should reject or separately version unsupported values rather than silently inventing incompatible canonical bytes.

## Golden vectors

See:

`protocol/browser-canonicalization-vectors.json`

Each vector publishes:

- input JSON;
- exact canonical UTF-8 JSON string;
- SHA-256 of those bytes.

## Versioning rule

A future canonicalization rule that changes canonical bytes must use a new canonicalization identifier. It must not silently redefine `sorted-json-v1`.

## Why this is explicit

Two runtimes can both say "sorted JSON" and still disagree on bytes. Cryptographic interoperability requires the bytes—not merely the data structure—to match.

## Claim boundary

This profile is a project-defined prototype contract. It is not an IETF, W3C, WHATWG, ISO, or other externally ratified canonicalization standard.
