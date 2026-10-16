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
The CLI requires strict UTF-8 and rejects duplicate JSON object names in every
input file, including escaped spellings of the same name and duplicates nested
in signed reports. A malformed byte sequence or duplicate name is a usage
error (exit `1`), even when lossy decoding or last-key-wins parsing would
produce a valid quorum. The browser API accepts already-parsed objects and
cannot recover source-byte errors or duplicate names from them.
It derives distinctness from the P-256 public point. Two JWK envelopes for the
same key with different optional metadata still count as one key, even if the
envelope fingerprints differ. The signed-report checker requires canonical
unpadded base64url coordinates; changing unused encoding bits does not create
a second key or a valid alternate signed envelope.

### Check against your own retained expectations

The saved quorum supplies its own artifact hash, keys, and threshold. A producer
can generate two keys and sign two reports. For a decision tied to known inputs,
retain a separate policy that you chose **before** receiving the quorum:

```json
{
  "schema": "aml-signed-quorum-held-policy/1",
  "prototype": true,
  "artifact_type": "aml-witness-bundle/1",
  "artifact_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "trusted_key_fingerprints": [
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  ],
  "threshold": 2
}
```

Replace the example hashes with the expected artifact hash and key fingerprints
you obtained independently of the quorum. Then run:

```bash
aml verify-signed-quorum saved-quorum.json --policy held-policy.json
```

The result keeps three separate booleans: `valid` checks the saved object's
internal consistency; `threshold_met` checks the saved threshold using all
valid endorser keys; `policy_met` checks the expected artifact and the policy's
own threshold using only allowlisted keys with valid signatures and positive
reports. With a policy, exit `0` requires all three. Exit `2` means a quorum
or policy condition failed; malformed verifier-held policy is a usage error
(exit `1`). The policy must be kept separately from the untrusted quorum.
Allowlisting keys does not establish the operators' independence or the truth
of their reports. The policy lists envelope fingerprints so that the checker
can recognize pinned public-key documents; key distinctness is still measured
from the public key material.

If you need endorsements from separately chosen trust groups, use the
versioned buyer-held policy below. Obtain each fingerprint and its group
assignment independently of the saved quorum, then retain this policy before
receiving reports:

```json
{
  "schema": "aml-signed-quorum-held-policy/2",
  "prototype": true,
  "artifact_type": "aml-witness-bundle/1",
  "artifact_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "trusted_keys": [
    { "verifier_key_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "trust_group": "lab-a" },
    { "verifier_key_fingerprint": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "trust_group": "lab-b" }
  ],
  "threshold": 2,
  "group_threshold": 2
}
```

The same `--policy` option accepts all three versions. Version 2 requires its key
threshold **and** its trust-group threshold among allowlisted, positively
signed reports about the pinned artifact. Both distinct keys and groups are
counted from the submitted reports; the trusted key list may contain groups
that never endorsed. A key's P-256 public point counts once, even if its JWK
metadata changes. If two pinned envelope fingerprints for that same public
point appear in positive signed reports and assign it to different groups,
`policy_met` is false and the conflicting key material is listed in
`policy_evaluation`. The checker cannot detect aliases that are absent from
the submitted reports using envelope fingerprints alone.

Trust-group labels are buyer-supplied lowercase identifiers of 1–64 ASCII
letters, digits, dots, underscores, or hyphens, beginning with a letter or
digit. They express the buyer's trust roster; they do not verify an operator's
identity, legal status, independence, control of a key, or the truth of a
report. Version 1 remains supported when group diversity is not required.

### Pin the public-key material in the held roster

Version 3 adds a SHA-256 fingerprint of each P-256 uncompressed public point
(`04 || x || y`) to each trusted-key entry. First obtain the public JWK through
a channel you trust independently of the saved quorum, then derive its two
identifiers:

```bash
aml fingerprint-verifier-key lab-a-public-jwk.json
```

The command prints `verifier_key_fingerprint` (the canonical complete JWK,
including optional metadata) and `key_material_fingerprint` (the raw P-256
public point). It accepts a public P-256 verification JWK; it rejects a JWK
containing private material. Fingerprinting identifies bytes, not the owner or
authorization of a key. Retain the JWK and your policy separately from the
quorum. Browser users can call `window.AML.fingerprintVerifierPublicKey(jwk)`
for the same calculation. For example, add the derived material fingerprints
to the version 2 policy and change the schema:

```json
{
  "schema": "aml-signed-quorum-held-policy/3",
  "prototype": true,
  "artifact_type": "aml-witness-bundle/1",
  "artifact_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "trusted_keys": [
    { "verifier_key_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "key_material_fingerprint": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "trust_group": "lab-a" },
    { "verifier_key_fingerprint": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "key_material_fingerprint": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "trust_group": "lab-b" }
  ],
  "threshold": 2,
  "group_threshold": 2
}
```

Version 3 rejects duplicate material fingerprints while validating the held
roster, including aliases for one key assigned to different
groups. It counts an endorsement only when its signed public key matches both
held fingerprints; a positively signed allowlisted report with a mismatched
material pin makes `policy_met` false and appears in
`policy_evaluation.mismatched_key_fingerprints`. It still requires the key and
group thresholds. An absent key document cannot be checked against its
claimed material fingerprint until it is supplied, and an invented group or
multiple keys controlled by one operator remain outside cryptographic proof.
The older policy versions remain available for existing consumers.

For cross-runtime checking of the saved quorum and held policy, use the
[project-authored Python verifier](../independent/python/verify_signed_quorum.py):

```bash
python3 independent/python/verify_signed_quorum.py saved-quorum.json --policy held-policy.json
```

It recomputes report signatures and the saved summary with Python's standard
library, including the distinct P-256 key count. It has a narrower documented
canonical JSON domain. It can also replay the named witness and retained
challenge using the same `--bundle` and `--challenge` options shown below.
Agreement between two implementations maintained in this repository is useful
interoperability evidence, not an independent institutional witness.

### Recheck the named witness bundle

If the reports name an `aml-witness-bundle/1`, supply the bundle and your own
separately retained challenge when verifying the quorum:

```bash
aml verify-signed-quorum saved-quorum.json \
  --policy held-policy.json \
  --bundle witness.json --challenge held-challenge.json
```

The standard-library Python verifier accepts the same input paths:

```bash
python3 independent/python/verify_signed_quorum.py saved-quorum.json \
  --policy held-policy.json \
  --bundle witness.json --challenge held-challenge.json
```

Its cross-runtime comparison harness generates a live bundle and signed
quorum, then checks both runtimes' five decision booleans and the indexed
conflicts on matching and adversarial inputs. The Python verifier rejects
JSON outside its documented portable subset, so its acceptance domain is
narrower than JavaScript's.

`witness_met` is a fourth, separate result. It requires the locally rechecked
bundle to pass with the retained challenge **now**, and requires its integrity
hash to match the signed quorum's artifact hash and type. When these inputs are
supplied, the CLI also requires `witness_met` for exit `0`. A changed challenge,
tampered bundle, mismatched artifact, or expired challenge fails this check.
Use `verifySignedVerificationQuorum(quorum, { policy, witnessBundle,
expectedChallenge })` for the same check in browser JavaScript. Supplying only
one of the bundle and challenge is a usage error.

When replay succeeds, `replayable_claims_consistent` checks every authenticated
positive report for explicit claims that contradict the local result: a
non-null session key fingerprint, a non-null challenge expiry, and any named
reference checks for bundle and receipt integrity, evidence integrity,
challenge freshness and binding, and session signature. An explicit
`checked_at` must be a canonical UTC millisecond timestamp within the
challenge's inclusive issue-to-expiry interval, and cannot precede the
bundle's or attestation's canonical creation time. A malformed, premature, or
late claimed check time is a reported conflict. These times are artifact and
signer assertions. The comparison cannot prove the signer actually performed
the check at that time; a trusted time
source would require separate evidence. The result includes
report indexes and conflicting field names. The CLI also requires this result
for exit `0` when the bundle and challenge are supplied. Omitted optional
fields and unknown check names make no claim that this comparison can test.
`verifier_held_challenge` describes what the signer did; a buyer replaying with
their own retained challenge cannot establish that the signer held one.

This is a local reference verifier replay of the supplied artifact. It does
not establish that the signers ran that verifier, that their other claims are
true, or that the signers are independent.

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
