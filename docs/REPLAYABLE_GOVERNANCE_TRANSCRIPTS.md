# Replayable ĀML governance transcripts

A live governance decision is useful while an interface is being generated. A replayable transcript makes the same session inspectable after the fact.

ĀML governance stream transcripts record the exact input/output sequence of a continuous governance session as a canonical SHA-256 hash chain and can deterministically replay the original inputs to verify that the recorded decisions are the ones the reference runtime produces.

Protocol:

```text
aml-governance-stream-transcript/1
```

## Generate a transcript

```bash
npm run governance-transcript > transcript.json
```

Or:

```bash
aml-governance-transcript conformance/governance-stream/mixed.ndjson > transcript.json
```

## Verify it

```bash
aml-governance-transcript-verify transcript.json
```

A successful verification reports both:

- `hash_chain_valid: true`
- `replay_valid: true`

These are intentionally separate checks.

## What the hash chain proves

Each transcript entry commits to:

- its sequence number;
- input vs output direction;
- the previous entry hash;
- the exact canonicalized message.

Changing, deleting, inserting, or reordering an entry breaks the chain unless the hashes are recomputed.

## Why replay verification is also required

A hash chain alone does not prove that the recorded outputs were truthful. Someone who controls a transcript could alter a decision and recompute every later hash.

ĀML therefore replays the recorded input messages through the governance stream and compares the resulting output sequence with the transcript.

That means a deliberately falsified output can still fail verification even after the attacker rebuilt a mathematically valid hash chain.

## What this does not prove

A hash chain is an integrity mechanism, not identity authentication.

An unsigned transcript does **not** prove:

- who created it;
- which organization operated the runtime;
- that a trusted machine produced it;
- that the transcript was observed by an independent party;
- that the underlying policy choices are scientifically or legally correct.

Signer identity, trusted execution, external witnessing, and independent implementation are separate evidence layers.

## Schema

- `schemas/governance-transcript.schema.json`

## Evidence boundary

The implementation and tests in this repository are project-controlled engineering evidence. They demonstrate that the reference implementation can create, tamper-check, and deterministically replay governance transcripts. They do not establish independent external reproduction or adoption.
