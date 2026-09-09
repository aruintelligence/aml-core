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

## What counts as an external witness

A passing run inside `aruintelligence/aml-core` does **not** count as outside adoption. To qualify for the public witness registry, the implementation/result must be maintained outside the canonical repository and backed by a stable public source or report.

PASS, FAIL, and MIXED reports are welcome. An ambiguity or failure in the contract is useful evidence and should not be hidden.

Submit outside results through the repository's `Independent replication` or `External verifier report` issue forms. Accepted public evidence may be recorded in `WITNESSES.json`.

## Evidence boundary

Passing this challenge is project-defined black-box interoperability evidence for the tested verifier contract. It does not establish certification, implementation independence by itself, endorsement, standards-body approval, safety, ethics, legal compliance, institutional authority, or broad adoption.

The external witness count remains whatever `WITNESSES.json` can actually substantiate.
