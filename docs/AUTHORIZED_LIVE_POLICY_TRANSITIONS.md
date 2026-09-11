# Authorized live policy transitions

ĀML continuous-governance sessions can optionally require cryptographic authorization before a live policy epoch is allowed to change.

This builds on replayable policy epochs. The stream still records the policy update and applied acknowledgement, but a protected session can additionally require an Ed25519 threshold authorization bound to the exact transition.

## Transition binding

Protocol:

```text
aml-governance-policy-transition/1
```

A transition binds signatures to:

- the stream transmission identifier;
- the expected current policy epoch;
- the exact previous policy-state SHA-256;
- the exact requested update fields.

That binding is intended to prevent an authorization for one update, one epoch, or one prior state from being silently reused for a different transition.

## Authorization envelope

Protocol:

```text
aml-governance-policy-transition-authorization/1
```

An authorization can contain multiple Ed25519 signatures. The verifier policy can require:

- a threshold greater than one;
- verifier-supplied trusted fingerprints;
- revoked fingerprint exclusion;
- a required signer scope;
- distinct signing keys.

A protected stream is opened with a `policy_authorization` policy. When `required: true`, a policy-update message without an eligible authorization is rejected before state mutation.

## Trust boundary

This is threshold authorization under an explicit cryptographic key policy, not organizational identity proofing or a universal authority system. Whoever configures the trusted fingerprint set determines which keys are eligible.

An embedded public key is not automatically trusted. Repository-generated test keys are project-controlled engineering fixtures. Official ĀRU authorization remains a separate trust-root and authorization question.
