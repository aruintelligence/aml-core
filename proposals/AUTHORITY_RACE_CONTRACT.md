# ĀML Authority Race Contract — design proposal (v0)

Status: **proposal, not implemented or independently validated**.

## Problem
A signed approval can be valid when inspected but revoked before a real tool dispatch. A valid signature, timestamp, or witness quorum does not alone establish current authorization. This is a time-of-check/time-of-use (TOCTOU) boundary.

## Required invariants
1. **Authority is host-owned.** A model, browser, caller, or supplied timestamp cannot declare a grant active.
2. **Bind exact bytes.** A grant binds canonical prepared request digest, policy digest, actor, audience, tool, tenant, and unique grant ID. A digest mismatch denies.
3. **Atomic consume.** The host records one successful consume per grant ID using a transactional compare-and-set or uniqueness constraint; concurrent attempts cannot both dispatch.
4. **Fresh revocation.** Before dispatch, the host reads a monotonic issuer revocation epoch from an authoritative store. A stale or unavailable store yields `indeterminate` and **zero dispatches**, not allow.
5. **No replay after uncertainty.** If dispatch outcome is unknown (timeout after provider handoff), mark `outcome_unknown` and require provider-side idempotency/reconciliation; do not silently retry.
6. **No clock substitution.** Capture host time once for each validation step; caller-supplied times are test inputs only, never authorization clocks.
7. **Tenant isolation.** Revocation, grant ID, epoch, and idempotency namespace include tenant identity.
8. **No false security claims.** These invariants only hold if the actual provider dispatch path is behind the host-owned guard.

## Proposed state machine

`issued -> eligible -> reserved -> dispatched -> acknowledged`

Terminal alternatives: `denied`, `revoked`, `expired`, `outcome_unknown`.

- `eligible -> reserved` must be atomic and include an epoch comparison.
- Revocation occurring **before reservation** must deny.
- Revocation occurring **after reservation but before provider dispatch** requires a second authoritative check or a serialized lock covering dispatch handoff; otherwise document the residual race and do not claim revocation-at-dispatch guarantees.
- A reservation that times out must not become reusable without verified evidence that no provider dispatch occurred.

## Minimal host pseudocode

```text
prepared = canonicalize(provider_request)
binding = sha256(prepared)
assert server_authority.validate(grant, binding, tenant, tool, audience)
assert server_authority.check_epoch(grant.issuer, tenant) == grant.epoch
reservation = store.atomic_reserve(grant.id, tenant, binding, grant.epoch)
if !reservation.success: DENY
if server_authority.check_epoch(grant.issuer, tenant) != grant.epoch:
    store.mark_revoked(reservation); DENY
store.mark_handoff_started(reservation)
try:
    response = provider.dispatch(prepared, idempotency_key=reservation.id)
    store.record_response(reservation, response)
except uncertain_transport_failure:
    store.mark_outcome_unknown(reservation)
    DO_NOT_RETRY_WITHOUT_RECONCILIATION
```

**Caveat:** The pseudocode's second epoch check is not an atomic guarantee against revocation between that check and dispatch. Strict linearizable revocation-at-handoff requires a shared serialization boundary, or the contract must explicitly define revocation as effective for *new reservations* rather than already-reserved dispatches.

## Adversarial acceptance tests
| Case | Expected |
|---|---|
| Two simultaneous consumes of one grant | At most one reserved |
| Revoked issuer before reservation | Zero dispatch |
| Epoch store unreachable | Zero dispatch, indeterminate |
| Grant from tenant A used in tenant B | Zero dispatch |
| Prepared request differs by one BCC recipient | Zero dispatch |
| Grant signature valid but audience differs | Zero dispatch |
| Provider timeout after handoff | Outcome unknown; no blind retry |
| Stale replicated revocation state | Zero dispatch or explicit weaker consistency contract |
| Caller backdates evaluation clock | No change in host decision |
| Grant expires while waiting for reservation | Zero dispatch |

## Evidence requirements
Record sanitized canonical digests, issuer epoch, grant ID hash, tenant ID hash, server timestamp, reservation transition, provider idempotency key hash, and explicit `dispatch_count` from a mock provider. Never include raw secrets, private recipients, or tokens in public proof artifacts.

## Release gates
- Unit tests for every case above and concurrency stress tests.
- Fault-injection with a delayed revocation store and uncertain provider responses.
- Cross-runtime canonicalization vectors (JS/Python/browser where relevant).
- A documented external integration test before any claim of live protection.
- Security review of the actual host dispatch wrapper.

## Commercial value hypothesis
A verifiable approval-to-action boundary could help enterprises audit AI-initiated tool calls and reduce unauthorized execution risk. Pricing, customer demand, compliance suitability, and operational reliability remain unvalidated.
