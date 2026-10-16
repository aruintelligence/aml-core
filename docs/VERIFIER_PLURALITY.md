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

The quorum requires each report's verdict to be a boolean and its artifact
type and hash to be nonempty strings. The signed-key quorum applies the same
checks to **every** report with a valid signature before counting it; a valid
signature over a missing artifact hash or a string such as `"false"` cannot
increase the endorsement threshold. Signature validity proves key possession
over the report bytes, not that the report's claims are true.
Signed report verification also rejects live JavaScript fields that are hidden,
symbol-keyed, or otherwise omitted from signed JSON. Exchange ordinary JSON
reports so a visible claim cannot sit outside the signed bytes.

The unsigned quorum reports:

- number of distinct verifier IDs;
- valid reports;
- invalid reports;
- whether a configured threshold was met;
- whether all supplied reports were unanimous;
- disagreement reasons.

## Recheck an exported signed quorum

Use `verifySignedVerificationQuorum(savedQuorum)` after JSON transport. It
verifies each embedded report signature, rebuilds the key counts and threshold
summary, and compares the complete saved object with the rebuilt version.
It also checks that the claim-boundary text was not rewritten. A consistent
quorum can have `valid: true` and `threshold_met: false` when too few distinct
keys endorsed a valid report. The check establishes internal consistency of
the supplied reports; it cannot establish verifier independence or whether
their underlying verdicts were correct.

From a checkout or installed preview package, the offline command is:

```bash
aml verify-signed-quorum saved-quorum.json
```

It prints the verification result as JSON. Exit `0` requires both a consistent
quorum and a met threshold; exit `2` means rejection or an unmet threshold;
exit `1` means usage or unreadable/malformed JSON. This command is in the
current preview checkout, not the pinned `v1.3.0` stable package. The saved
signed quorum counts distinct valid endorser **keys**, and accepts at most 64
supplied reports.

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
