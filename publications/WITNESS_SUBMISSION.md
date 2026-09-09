# Submit an ĀML External Witness

**Status: SHIPPED submission protocol; external witness count remains evidence-driven**

An outside implementation can report PASS, FAIL, or MIXED results without asking the canonical repository to translate prose into a registry entry.

## 1. Produce public outside evidence

Maintain the verifier or reproduction outside `aruintelligence/aml-core` and publish a stable HTTPS source/report URL.

## 2. Create `aml-witness-record/1`

Start from [`../conformance/witness-record.example.json`](../conformance/witness-record.example.json). Replace every example identity and URL with the real outside evidence.

The result vocabulary is exact:

- `PASS` — the tested contract reproduced as expected;
- `FAIL` — the tested contract did not reproduce or verification failed;
- `MIXED` — partial success, disagreement, ambiguity, or inconsistent reproduction.

Negative evidence is welcome and is not downgraded or hidden.

## 3. Validate before submitting

```yaml
- id: aml-witness
  uses: aruintelligence/aml-core/actions/witness-record@main
  with:
    record-file: witness-record.json
```

Or:

```bash
node scripts/validate-witness-record.mjs witness-record.json
```

The canonical registry guard uses the same validator.

## 4. Submit the evidence

Use the `External verifier report` or `Independent replication` issue form and include the validated JSON record plus reproduction details.

A record is not added automatically merely because its JSON validates. Maintainers still review whether the evidence is actually public and maintained outside the canonical repository.

## Machine-checkable vs evidence-review boundary

The validator can check structure, result vocabulary, UTC observation time, HTTPS URLs, unexpected properties, and whether the supplied evidence URL points back at canonical ĀML evidence.

It cannot establish from JSON alone that an outside implementation is genuinely independent, that a report is truthful, or that a verifier is technically correct. Those are evidence-review questions.

A registry entry means only that a public outside source reported the recorded result. It does not imply endorsement, certification, standards-body approval, safety, ethics, legal compliance, trademark authorization, or broad adoption.
