# ĀML turns live governance into replayable evidence

A live ALLOW/SUPPRESS decision is useful in the moment. A portable transcript makes that decision challengeable later.

ĀML now has a project-defined governance transcript that records the exact input/output sequence of a continuous governance session, chains every entry with canonical SHA-256 hashes, and deterministically replays the recorded inputs to verify the recorded outputs.

This creates two independent checks inside the reference implementation:

1. **Hash-chain integrity** — detects ordinary modification, deletion, insertion, or reordering of transcript entries.
2. **Deterministic replay** — detects falsified recorded outputs even if someone recomputes the entire hash chain after changing them.

Generate an artifact:

```bash
npm run governance-transcript > transcript.json
```

Verify it:

```bash
aml-governance-transcript-verify transcript.json
```

The transcript contract is:

```text
aml-governance-stream-transcript/1
```

A valid verification requires both the transcript chain and the deterministic replay to agree.

## Why this moves the architecture forward

The continuous governance stream moved ĀML between generation and rendering while an interface is still being assembled.

Replayable transcripts add a second dimension: the live session can now become a portable artifact that another evaluator can inspect after the session has ended.

That makes it possible to ask stronger questions:

- Was the recorded stream altered?
- Did the recorded outputs actually follow from the recorded inputs?
- Can another implementation replay the same transcript and reach the same decisions?
- Where does cross-runtime disagreement begin?

## Critical boundary

A hash chain is not a signature.

An unsigned transcript does not establish the identity of its creator, prove that a trusted organization operated the runtime, or turn project-controlled evidence into independent evidence. Those require separate signing, trust, and witness layers.

This publication describes a shipped technical milestone in the ĀML research prototype. It is not a claim of external validation, certification, broad adoption, or standards-body recognition.
