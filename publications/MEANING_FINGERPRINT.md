# ĀML Meaning Fingerprint

**Status: preview implementation on `main`; experimental protocol surface, not a ratified standard**

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## The idea

Source code has file hashes. Builds have artifact hashes. ĀML now has a deliberately narrower experiment: a hash of the **Abstract Meaning Tree** produced from an ĀML source file.

A Meaning Fingerprint answers:

> Did the compiled meaning change?

The implementation compiles source into the ĀML Abstract Meaning Tree (AMT), wraps that tree in a domain-separated `aml-meaning-material/1` object, serializes it with ĀML's strict canonical JSON implementation, and computes SHA-256 over those UTF-8 bytes.

The resulting record uses the experimental protocol identifier:

```text
aml-meaning-fingerprint/1
```

This is not a claim that SHA-256 can determine human intent, truth, morality, or subjective meaning. It is a deterministic fingerprint of the **meaning structure ĀML itself compiled**.

## Why this is different from hashing the file

These two files are textually different:

```aml
transmission "demo" {
  engram card {
    purpose: "Explain clearly"
    attention_cost: 2
    restoration_value: 5
  }
}
```

```aml
// formatting and comments changed
transmission "demo" {

  engram card {
    purpose: "Explain clearly"
    attention_cost: 2
    restoration_value: 5
  }

}
```

Their source-file hashes differ. Their ĀML Meaning Fingerprint is the same because comments and whitespace do not survive into the AMT.

Change this:

```aml
purpose: "Explain clearly"
```

to this:

```aml
purpose: "Create urgency"
```

and the fingerprint changes.

## API

```js
import {
  meaningFingerprint,
  compareMeaningFingerprints
} from "aml-core";

const fingerprint = meaningFingerprint(source);
console.log(fingerprint.fingerprint);

const comparison = compareMeaningFingerprints(before, after);
console.log(comparison.equivalent);
```

## CLI

Fingerprint one file:

```bash
node bin/aml-meaning.js interface.aml
```

Compare two files:

```bash
node bin/aml-meaning.js before.aml after.aml
```

Exit codes for comparison:

- `0` — the AMT fingerprints are equivalent;
- `1` — compiled meaning differs;
- `2` — invalid invocation, unreadable input, or compilation error.

That makes the command usable directly in CI.

## Meaning Lock — GitHub Action

A repository can fail a refactor when compiled meaning changes:

```yaml
- uses: aruintelligence/aml-core/actions/meaning-lock@main
  with:
    before-file: before.aml
    after-file: after.aml
```

This is intentionally stricter and simpler than Meaning Gate. Meaning Gate evaluates semantic risk and policy regressions. Meaning Lock answers one binary question: **are these two compiled AMTs byte-equivalent under the published fingerprint material contract?**

## Semantic diff integration

`semanticDiff()` now reports:

```json
{
  "meaning_equivalent": false,
  "left_meaning_fingerprint": "…",
  "right_meaning_fingerprint": "…",
  "fingerprint_protocol": "aml-meaning-fingerprint/1"
}
```

The detailed semantic diff still explains what changed. The fingerprints give that explanation a deterministic before/after identity.

## What the fingerprint binds

Version 1 binds the full AMT object emitted by the current compiler, including its ordered tree structure, node types, identifiers, properties, inferred meaning, and render metadata.

The material is domain-separated before hashing:

```json
{
  "protocol": "aml-meaning-material/1",
  "amt": { "...": "compiled Abstract Meaning Tree" }
}
```

The material is serialized with the repository's strict canonical JSON implementation before SHA-256.

## What it does not prove

A matching fingerprint does **not** prove that two arbitrary programs behave identically, that an interface is ethical, that declared meaning is truthful, that a user will perceive two interfaces identically, or that ĀML is a ratified standard.

It proves something smaller and testable: under the declared `aml-meaning-material/1` contract and this compiler's AMT semantics, the canonical meaning material hashes to the same value.

That boundary is the feature.
