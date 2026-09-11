# Cross-runtime disagreement localization

ĀML can compare two governance-stream transcripts and identify the first observable point where they diverge.

This is intended for interoperability testing between distinct runtimes, language implementations, deployment modes, or policy engines that claim to implement the same public contracts.

## CLI

```bash
aml-runtime-disagreement left.json right.json \
  --left-runtime node-reference \
  --right-runtime external-runtime
```

Exit codes:

- `0`: transcripts are observably equivalent;
- `2`: a divergence was localized;
- `1`: malformed invocation or processing error.

## Output

Protocol:

```text
aml-runtime-disagreement-report/1
```

The report records:

- whether the observable transcripts are equivalent;
- whether transcript roots match;
- whether entry counts match;
- optional runtime labels;
- the first divergent sequence number;
- a divergence category;
- canonical SHA-256 hashes for the left and right entries.

Possible divergence categories include missing entries, direction mismatches, protocol mismatches, decision mismatches, input mismatches, and other output mismatches.

## What it does not decide

Localization does not determine which runtime is correct. A disagreement can arise from a bug, a version mismatch, a policy mismatch, different inputs, nondeterminism, an implementation choice outside the public contract, or an invalid transcript.

Correctness therefore requires a separate contract, conformance vector, witness policy, or human/organizational adjudication step.

This distinction is intentional: ĀML should make disagreement inspectable without pretending that one implementation is automatically authoritative.
