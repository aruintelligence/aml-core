# ĀML External Verifier Challenge

**Status: SHIPPED challenge surface; external witnesses remain zero until outside evidence exists**

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

## One executable. Four black-box cases.

An outside implementation can test ĀML verifier compatibility without importing the JavaScript reference verifier and without wrapping the `aml` CLI.

Your repository supplies one executable command. The ĀML harness invokes it as:

```text
<verifier-command> --now <ISO-8601> <bundle.json>
```

The verifier must emit one JSON object containing a boolean `valid` field. A valid bundle must exit `0`; an invalid bundle must exit nonzero.

The machine-readable contract is [`conformance/verifier-challenge.json`](../conformance/verifier-challenge.json).

## Start without reading the reference verifier

The `AML External Verifier Kit` workflow publishes a downloadable artifact containing only the public challenge, protocol text, JSON Schemas, canonicalization/test vectors, the JSON witness fixture, and witness-submission material.

The kit intentionally excludes JavaScript, Python, Go, Rust, Java, C/C++, C#, Swift, Zig, shell, and other reference implementation source files. Its `manifest.json` records every included path, byte count, SHA-256 digest, source commit, and one aggregate kit root. `SHA256SUMS` is generated from the same sorted material.

This makes an implementation clean-room-friendly by reducing accidental exposure to reference verifier code. It does **not** by itself prove that an implementation is independent; that remains an external evidence question.

## Drop it into GitHub Actions

In an independently maintained repository:

```yaml
- uses: actions/checkout@v4

- id: aml-conformance
  uses: aruintelligence/aml-core/actions/verifier-conformance@main
  with:
    verifier-command: ./verify.sh

- run: |
    echo "passed=${{ steps.aml-conformance.outputs.passed }}"
    cat "${{ steps.aml-conformance.outputs.result-file }}"
```

For a reproducible evaluation, pin the Action to an immutable ĀML release tag or commit after selecting the contract you intend to test.

`verify.sh` belongs to the outside implementation. It may launch Rust, Go, Python, Java, C#, Swift, Zig, C/C++, or another runtime, but it must not import the ĀML reference implementation if the result is being presented as independent reproduction.

## Cases

The current challenge runs:

1. `golden-valid` — the published witness must verify;
2. `tampered-purpose` — changed receipt purpose must be rejected;
3. `tampered-challenge` — changed challenge nonce must be rejected;
4. `expired-challenge` — the otherwise valid witness must be rejected after expiry.

The harness emits `aml-verifier-conformance-result/1` with the observed exit code, parsed validity, stdout/stderr, and per-case PASS/FAIL result.

## Turn the result into a machine-checkable witness record

The public witness registry uses `aml-witness-record/1`. A template lives at [`conformance/witness-record.example.json`](../conformance/witness-record.example.json).

Validate the record in the outside repository before submitting it:

```yaml
- id: aml-witness
  uses: aruintelligence/aml-core/actions/witness-record@main
  with:
    record-file: witness-record.json

- run: |
    echo "valid=${{ steps.aml-witness.outputs.valid }}"
    echo "witness=${{ steps.aml-witness.outputs.witness-id }}"
    echo "result=${{ steps.aml-witness.outputs.result }}"
```

Or run the validator directly from a checkout:

```bash
node scripts/validate-witness-record.mjs witness-record.json
```

The same validator is used by the canonical `WITNESSES.json` registry guard. That prevents the registry and the submission instructions from drifting into different acceptance formats.

The machine-checkable profile verifies structure, required fields, PASS/FAIL/MIXED result values, UTC observation time, HTTPS evidence URLs, and that the source/report URL does not point back at the canonical `aruintelligence/aml-core` repository or its GitHub Pages evidence surface.

It deliberately **cannot prove independence or truth merely from JSON**. Maintainer identity, actual implementation independence, and whether the public report accurately describes the experiment remain evidence-review questions. A self-declared `external_to_aml_core: true` flag is not sufficient if the supplied source URL is canonical project evidence.

## What counts as an external witness

A passing run inside `aruintelligence/aml-core` does **not** count as outside adoption. To qualify for the public witness registry, the implementation/result must be maintained outside the canonical repository and backed by a stable public source or report.

PASS, FAIL, and MIXED reports are welcome. An ambiguity or failure in the contract is useful evidence and should not be hidden.

Submit outside results through the repository's `Independent replication` or `External verifier report` issue forms. Accepted public evidence may be recorded in `WITNESSES.json` only after the record passes the machine validator and the outside evidence is reviewed.

## Evidence boundary

Passing this challenge is project-defined black-box interoperability evidence for the tested verifier contract. Passing the witness-record validator proves only that the submission matches the machine-checkable acceptance profile. A valid verifier-kit manifest proves only the integrity and declared code-exclusion profile of that generated kit. None establishes certification, implementation independence by itself, endorsement, standards-body approval, safety, ethics, legal compliance, institutional authority, or broad adoption.

The external witness count remains whatever `WITNESSES.json` can actually substantiate.
