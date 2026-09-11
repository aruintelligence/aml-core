# A live AI-interface policy change can require multiple trusted signatures before it takes effect

ĀML's streaming governance can already record policy epochs. The next question is authority: who is allowed to change those defaults while an interface is still being generated?

ĀML now includes a project-defined threshold authorization primitive for live governance-policy transitions.

The signed transition is bound to the stream, current epoch, exact previous policy-state hash, and exact requested update. A protected stream can require a configurable threshold of distinct eligible Ed25519 keys before applying the transition.

Verifier policy controls the trusted fingerprint set, revoked fingerprints, signer scope, and threshold. Missing authorization, insufficient eligible keys, duplicate-key inflation, or an authorization bound to a different requested update is rejected before policy state mutates.

Protocols:

```text
aml-governance-policy-transition/1
aml-governance-policy-transition-authorization/1
```

This moves the prototype from merely recording live policy mutation toward **cryptographically constrained governance mutation**.

The boundary remains explicit: trusted-key configuration is itself an authority decision. This mechanism does not prove real-world identity, organizational approval, regulatory status, independent validation, or official ĀRU authorization unless those properties are separately established.
