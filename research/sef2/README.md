# SEF/2 — independent-authority research fixture

Experimental, synthetic-only Python 3 reference. No production payment effects, no public protocol commitment, no independent validation. Builds on the SEF/1 branch without modifying its implementation.

## Run

```bash
cd research/sef2
python3 -W error::ResourceWarning -m unittest -v test_sef2
```

The test runner starts two localhost HTTP services: an authority that stores one-use approved operation/digest pairs and a synthetic provider that must ask that authority to consume an approval before recording a fixture effect. Administrative approval is not exposed over HTTP. The provider-to-authority request is authenticated with an HMAC key unavailable to the simulated agent. The authority and provider use separate SQLite stores.

## Tested properties (local only)

- Missing approval and unauthenticated direct authority access are denied.
- Destination mutation and replay are denied.
- Twelve concurrent requests yield one provider-reported synthetic effect.
- Deleting the provider row does not restore the consumed authority approval.
- Duplicate JSON object keys are denied.

## Explicit limitations and falsification targets

This is **not** an independently administered remote domain: both services run on one local host and share a secret. An attacker with host administrator access or provider credentials can bypass this model. The shared HMAC has no rotation, transport encryption, request freshness, or replay-resistant service authentication. The HTTP authority is bound to loopback and is not suitable for network deployment. There is no issuer signature, consent verification, revocation, policy epoch, independently signed provider receipt, external witness, durable cross-service atomicity, or safe reconciliation after a crash between approval consumption and effect. A provider failure after authority consumption leaves an ambiguous/blocked operation. Provider records are not proof of external completion.

The prototype deliberately does not replace the SEF/1 signed-authorization implementation; integration with the existing wire profile requires separate compatibility review. The attacker cannot choose approval records, service secrets, database files, or service code in the tested model.

Next: test separate VMs/administrative domains, mTLS with rotation, independent durable witness, explicit uncertainty recovery, and provider-side idempotency. Preserve all failed experiments.
