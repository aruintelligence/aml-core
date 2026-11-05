# Execution integrity contract — draft 0.1

Status: **design**, with partial local reference behavior in `pilots/action-boundary/`. This document does not assert that a provider or external operation completed.

## States that must remain distinct

| State | Evidence a host needs | What it does not establish |
| --- | --- | --- |
| Proposal captured | Canonical proposal bytes and SHA-256, tool, resource, effect, policy identity | Human consent or actual target |
| Policy decision | Host-held policy snapshot and decision at an identified epoch | Future policy validity |
| Approval recorded | Authenticated approver, scope, digest, expiry, grant ID | One-use consumption or dispatch |
| Grant consumed | Durable atomic claim and issuer epoch check | A request was sent |
| Request initiated | Operation ID, exact provider request digest, dispatch attempt/time | Provider acceptance |
| Provider accepted | Provider acknowledgment or durable idempotency record tied to operation ID | External completion |
| External operation completed | Provider completion evidence with external identifier | Independent confirmation |
| Independently confirmed | Separately obtained observation with provenance and reconciliation time | Universal or permanent truth |
| Outcome uncertain | Timeout, crash, ambiguous response, or incomplete journal | Failure or permission to retry |

`blocked` means the guarded path did not invoke its callback. `dispatched` in `aml-action-dispatch/1` means the callback returned; existing receipt semantics must not be silently upgraded to "provider accepted". A new provider-state receipt should use a new schema/protocol and bind the earlier proposal, policy epoch, grant ID, operation ID, request digest, prior-state digest, time and evidence references. A SHA-256 digest without a trusted signature/key or independently retained anchor is tamper detection against accidental byte changes, not provenance.

## Reference transition rules

The host records an intent ID separately from the proposal digest: two deliberate identical actions may have distinct IDs. The grant may move `issued → consumed` only once, atomically and durably. The host rechecks revocation at the linearization point and, where required, at provider handoff. After claim, `request_initiated → provider_accepted → completed → independently_confirmed` requires evidence at each transition. A timeout after initiation moves to `outcome_uncertain`; it does **not** move to `blocked` or `completed`. A crash after consumption but before request remains consumed and uncertain. Revocation after an irreversible provider acceptance cannot undo the effect.

`pilots/action-boundary/provider-execution-state.mjs` is an experimental in-memory reducer for these distinctions. Protocol `/2` binds one host operation ID and proposal digest, accepts only named transitions with nonempty host-supplied evidence references, and retains immutable snapshots. It remembers which milestone became uncertain. Reconciliation can advance only one stage from request initiated to provider accepted, provider accepted to completed, or completed to independently confirmed. Uncertainty directly after a consumed grant remains unresolved in this reducer; a host must investigate before deciding on any separate authorized operation. The prior `/1` reducer allowed an uncertainty-to-completion jump without a recorded provider acceptance; do not rely on that version. The reducer does not authenticate references, persist them, sign receipts, observe a provider, or coordinate a grant store. A host must supply those functions before using its states as external evidence.

For a provider offering idempotency keys, derive a provider-scoped key from a **host-generated stable operation ID**, retain the key through retries, and verify the provider's retention window and semantics. An automatic retry is allowed only when a provider contract and reconciliation evidence establish that it cannot duplicate the external effect. Otherwise, freeze the operation for operator review. Distinguish cancellation requests, confirmed cancellation, and rollback or compensation; they are separate actions with their own authorization and evidence.

## Trust and failure boundaries

The host must own policy, identity verification, exact tool/target mapping, grant storage, trusted clock, provider credentials and side-effect callback. Any bypass path invalidates the guarded-path claim. Local file markers require private storage, durable directory entries, careful crash recovery and no network filesystem assumptions. The fixed `file-one-shot-grants.mjs` prevents a particular partial-store replay, but cannot detect whole-store rollback after restart or resist same-identity tampering. The existing stronger `file-revocation-handoff.mjs` has optional external claims/checkpoints; these are project-authored pilots, not a production distributed store.

A controlled complete-snapshot probe makes the limit executable: a valid grant-store snapshot taken before claim, restored after claim, permits a second claim (`node pilots/action-boundary/file-grant-rollback-probe.mjs`). An anti-rollback claim therefore requires a trust domain outside the rollbackable directory. At minimum, an independently retained coordinator must atomically decide each `(issuer, grant_id)` consumption and policy/revocation epoch, reject reuse after restart, retain its state beyond local snapshot restoration, and fail closed when unavailable. The host must check that decision before entering the protected callback and bind its operation/proposal identity to the coordinator transaction. A locally saved signature, hash chain, or second file in the same rollback domain does not meet this condition. Coordinated databases, witnesses and provider idempotency still require separate crash, split-brain, rollback, and side-effect tests before any production or exactly-once claim.

## Acceptance work before production

Implement a transactional external claim and revocation epoch under one linearizable store; bind provider idempotency and independently held completion evidence; exercise crashes at every state boundary; document reconciliation and retention; test multi-worker and multi-host races; obtain an external review. Existing `aml-action-dispatch/1` receipts remain valid under their documented limited meaning.

## Narrow local uncertainty fixture

`pilots/action-boundary/local-provider-recovery.mjs` now demonstrates one bounded failure: a child provider writes an exclusive local effect marker and exits without acknowledgment. The host state remains `outcome_uncertain` until a second process reads the provider's matching operation/request record, then may label the fixture `completed`; it never labels it `independently_confirmed`. An exit before write leaves uncertainty, even when this fixture's store is empty. The one-use grant rejects replay and the host does not automatically retry. This project-authored simulation is not a durable host journal, actual network send, authenticated provider evidence, or real-world completion verifier. A full verified execution protocol still needs those properties and independent evaluation.

A separate host-restart extension persists an event snapshot after `request_initiated`, exits the host process after the provider child writes or declines an effect, and starts a new host process that replays transitions and reconciles. The provider record is still unauthenticated local fixture evidence. This demonstrates one crash window and safe refusal to retry; it does not establish that every crash window is safe, nor that a malicious provider or same-identity actor cannot forge completion.
