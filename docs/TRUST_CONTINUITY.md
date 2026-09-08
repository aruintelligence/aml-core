# ĀML™ Trust Continuity

ĀML began by making a single render decision inspectable. The v1.3 trust-continuity work extends that idea across time, policy disagreement, provenance, consent changes, and large batches of execution receipts.

## 1. Time-scoped, revocable consent

A static boolean such as `consent_granted: true` is not enough for long-lived systems. ĀML now includes a hash-chained consent ledger that records scoped grants and revocations.

A consent grant can expire. A later revocation supersedes an earlier grant. Mutation of a historical event breaks ledger verification.

This lets a runtime derive context from an auditable history instead of assuming consent is permanent.

## 2. Policy consensus with explicit dissent

Policy composition normally collapses several rules into one final allow/suppress outcome. ĀML now supports consensus evaluation that preserves each policy's vote and records dissent.

Supported strategies include majority, unanimous, and any-policy-may-allow. Weighted votes are also supported.

The purpose is not to claim that majority voting produces ethical truth. The purpose is to prevent disagreement from disappearing inside a final Boolean.

## 3. Hash-bound provenance graph

An accountable execution receipt can now be represented as a provenance graph connecting:

```text
intent
  ↓
generated AML
  ↓
policy simulation
  ↓
render decision
  ↓
rendered output
```

The graph also binds the runtime audit stream and cumulative attention ledger into the final execution receipt. The complete graph is SHA-256 bound so mutation can be detected.

## 4. Merkle-batched execution receipts

Large systems may produce thousands or millions of execution receipts. Publishing every receipt to prove that one receipt existed in a committed set can be unnecessary and privacy-hostile.

ĀML now supports Merkle batching of receipt hashes.

A system can publish one Merkle root and later produce an inclusion proof for a single receipt without revealing every other receipt in the batch.

This can support independently verifiable audit windows while minimizing unnecessary disclosure.

## 5. Trust is still bounded

These mechanisms prove specific technical properties:

- consent-history integrity;
- policy disagreement preservation;
- artifact provenance binding;
- receipt membership in a committed batch;
- mutation detection.

They do **not** prove that declared intent is truthful, that a policy is morally correct, that consent was legally sufficient, or that a signer is institutionally trustworthy.

ĀML's design goal remains narrower and testable: make the decision chain explicit enough that those questions can be examined instead of hidden.

## The emerging architecture

```text
AI intent
  ↓
ĀML source
  ↓
semantic + accessibility analysis
  ↓
policy matrix / consensus
  ↓
time-scoped consent context
  ↓
render decision
  ↓
cumulative attention accounting
  ↓
runtime audit stream
  ↓
execution receipt
  ↓
provenance graph
  ↓
Merkle batch / inclusion proof
```

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**
