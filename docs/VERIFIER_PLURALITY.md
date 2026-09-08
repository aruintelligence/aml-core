# Verifier Plurality

**Status: SHIPPED reference prototype**

## One idea

One verifier can be wrong. ĀML therefore publishes a prototype path for comparing multiple verifier reports over the **same exact artifact hash**.

The core object is:

```text
aml-verification-quorum/1
```

A quorum aggregates `aml-verification-report/1` objects only when they agree on:

- artifact type;
- exact artifact hash;
- distinct declared verifier IDs.

It reports:

- number of distinct verifier IDs;
- valid reports;
- invalid reports;
- whether a configured threshold was met;
- whether all supplied reports were unanimous;
- disagreement reasons.

## What this does not prove

A distinct `verifier` string does **not** prove that the implementation is operated by a distinct institution, written independently, uncompromised, or correct.

Threshold agreement is evidence that the supplied reports agree over the same exact artifact under this project-defined contract. It is not truth, certification, standards-body approval, or institutional trust.

## Machine-readable verifier capability discovery

A verifier may publish an `aml-verifier-manifest/1` document declaring:

- verifier ID;
- runtime;
- artifact types;
- report schema;
- canonicalization profiles;
- supported signature algorithms;
- source/verification URLs;
- claim boundary.

Reference manifests live under `protocol/verifiers/`.

## Example

```js
import { createVerificationQuorum } from './aml-verification-quorum.js';

const quorum = createVerificationQuorum([
  browserReport,
  pythonReport,
  httpReport
], { threshold: 2 });

console.log(quorum.summary);
```

Expected shape:

```json
{
  "distinct_verifiers": 3,
  "valid_reports": 3,
  "invalid_reports": 0,
  "threshold_met": true,
  "unanimous": true,
  "disagreement_reasons": []
}
```

## External witness goal

The meaningful milestone is not creating more in-repository verifier IDs. It is an **outside implementation** producing its own public verification report over the published golden witness vector.

Open the golden vector. Implement the verifier independently. Publish the report. Disagreement is useful evidence.
