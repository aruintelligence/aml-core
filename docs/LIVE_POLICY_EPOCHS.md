# Live governance policy epochs

ĀML continuous-governance sessions can change their default policy state while a generated interface is still streaming.

A policy transition is an explicit stream message:

```json
{
  "protocol": "aml-governance-stream-policy-update/1",
  "mode": "shadow",
  "context": { "rollout": "canary" }
}
```

The runtime acknowledges it with:

```text
aml-governance-stream-policy-applied/1
```

The acknowledgement includes a monotonically increasing policy epoch, the previous policy-state hash, the new policy-state hash, and a context hash.

Subsequent nodes use the new defaults unless a node explicitly supplies an allowed per-node override. Supported mutable defaults are:

- profile;
- enforce/shadow mode;
- open/closed failure mode;
- context, using merge or replace semantics.

Because both the update and its acknowledgement are recorded in governance transcripts, sessions containing policy changes can still be deterministically replayed and audited.

## Why this matters

Long-lived generative interfaces may move from shadow evaluation to enforcement, change rollout context, or change a policy profile while the interface is still being constructed. Silent mutable configuration would make later evidence ambiguous. Policy epochs turn that mutation into part of the observable protocol history.

## Boundary

This mechanism does not authorize a policy change. It records and applies one. Authorization, signer identity, quorum requirements, deployment controls, and organizational approval remain separate concerns that can be layered above the stream contract.
