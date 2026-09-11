# Multiple independent keys can attest to the same governed AI interface decision

ĀML's governance evidence path now supports a project-defined threshold witness layer.

A generated interface can be governed before rendering, streamed through continuous policy evaluation, archived as a replayable transcript, signed with Ed25519, and then evaluated against a multi-party witness policy.

The new quorum layer keeps several questions separate:

1. Is the transcript internally intact?
2. Does deterministic replay reproduce it?
3. Is each witness signature cryptographically valid?
4. Is each signing key trusted by the verifier's policy?
5. Is the key revoked?
6. Are enough distinct eligible keys attesting to the same transcript root?

Only the last question is the quorum decision.

This matters because "three signatures" should not automatically mean "three trusted independent witnesses." Duplicate keys are excluded by default, revoked keys can be rejected, and trust fingerprints are supplied by the verifier rather than inferred from embedded keys.

Protocol:

```text
aml-governance-witness-quorum/1
```

Reference implementation:

```text
protocol/governanceWitnessQuorum.js
```

CLI:

```bash
aml-governance-witness-quorum quorum-input.json
```

This is a shipped research-prototype capability. It is not a standards-body consensus mechanism, not a claim of independent external witnesses, and not evidence of adoption merely because the reference implementation can simulate multiple keys. Real E3/E4 evidence still requires outside parties to reproduce or independently implement the contract.
