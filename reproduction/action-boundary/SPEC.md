# Canonical action-boundary evidence specification

Version: `aml-action-boundary-evidence/1` (2026-10-20). This specification
describes the concrete receipt-binding implementation and the published JSON
subset. The executable definitions live in the linked source files.

## Proposal and policy

An `aml-proposed-action/1` object has exactly `protocol`, `tool`, `effect`,
`resource`, `purpose`, and `arguments`. The first five fields are bounded
strings except `effect`, which is one of `read`, `write`, `send`, `pay`, or
`delete`; `arguments` is a plain JSON object. The canonical UTF-8 proposal
must be at most 65,536 bytes. The digest is SHA-256 of
`canonicalJSONStringify(proposal)` from
[`protocol/canonicalJson.js`](../../protocol/canonicalJson.js). The fixture
subset excludes nonfinite numbers, unsupported JavaScript values, unsafe
integers, and object keys outside the documented cross-language subset.
Canonicalization recursively sorts object keys; JavaScript enumeration puts
array-index keys in numeric order. Array order is preserved. Reordering
ordinary object keys leaves the digest unchanged; changing a payload value,
recipient, declared resource, or invocation ID changes it.

The host owns `aml-action-policy/1`, an array of exact rules over `tool`,
`effect`, and `resource`, each with `requires_approval`. No matching rule,
ambiguous matching rules, invalid input, or invalid policy denies the plan.
An exact rule yields `allow` or `requires_approval`. A matching approval must
carry the frozen proposal digest. The host rechecks policy after any async
approval and immediately before dispatch, and passes a copy of the frozen
proposal to its callback. An optional atomic grant consumer is necessary for
cross-worker one-shot semantics. The generic boundary itself is
[`boundary.mjs`](../../pilots/action-boundary/boundary.mjs).

## Decision and receipt

The plan records `proposal_sha256`, `decision`, and `reason`. The dispatch
receipt records the same proposal digest, policy decision, execution status,
and reason. A blocked callback is `blocked`; a returned callback is
`dispatched`; a thrown callback is `unknown`, since a partial external effect
may have occurred. The compact dispatch receipt **does not** include a policy
hash. The challenge evidence envelope separately includes the full initial
host policy, its digest, the proposal, expected plan and receipt, callback
count, and a canonical `receipt_sha256` over the entire envelope excluding
that final hash. A self-computed hash detects mismatches against a pinned
artifact, but does not authenticate the publisher.

The four integration adapters issue a separate host-owned pre-dispatch
authorization receipt. Its body contains the full frozen proposal and host
policy, their digests, exact resolved target, plan, ALLOW/SUPPRESS decision,
reason, and nonce. `receipt_sha256` hashes that body. `host_mac_sha256` is a
host HMAC over the receipt hash. Dispatch verifies the MAC, frozen proposal,
current policy, resolved destination, and in-process one-use claim before
calling the provider. The public fixtures use a known test key; production
requires a private key and a durable grant store. See
[`receipt-adapters.mjs`](../../pilots/action-boundary/receipt-adapters.mjs).
The adapter rechecks the host policy and target after an awaited approval,
before issuing `ALLOW`. An observed change to either at dispatch spends the
grant, so restoring the earlier policy or target cannot revive it. The
[revocation cohort](../../docs/action-receipt-revocation-report.json) records
those transitions for four local provider shapes. An unobserved change that
returns to identical policy bytes requires a host epoch or durable revocation
record; the digest alone cannot reveal it.
With an optional host-owned `policyEpoch` callback, the authorization receipt
also binds `policy_epoch` as a nonnegative safe integer. The host must advance
it monotonically for policy and target-mapping changes. The adapter checks it
after approval and immediately before dispatch; a mismatch or unavailable
value blocks and spends the grant. The [epoch comparison](../../docs/action-receipt-policy-epoch-report.json)
demonstrates an unobserved A→B→A sequence using in-memory host state. Without
the option, existing receipt bytes remain unchanged. Durability and monotonic
ordering across processes are host obligations, not verified by the adapter.

## Published evidence and limits

The [100 challenge cases](../../conformance/action-boundary-expanded-cases.json)
specify exact inputs and outcomes. The [five-runtime matrix](../../docs/action-five-runtime-report.json)
reports 100/100 agreement in each project-maintained binding. The simulated
[375-case stress cohort](../../conformance/action-stress-375-cases.json)
specifies 25 profiles across five tool families and 15 mutation classes, with
full [evidence receipts](../../conformance/action-stress-375-receipts.jsonl)
and a [375-row runtime matrix](../../docs/action-stress-five-runtime-report.json).
These are simulated host callbacks; the WebCrypto stress binding ran in Node.
The observed
[Chrome run](../../docs/evidence/aml-action-browser-100.json) independently
records the deployed browser result. Ten pairs of controlled public pages
publish before and after screenshots, full DOM snapshots, source checkpoints,
labels, decisions, and SHA-256 receipts under
[`docs/action-pilots`](../../docs/action-pilots). The [registry](../../registry/README.md)
hash-chains the distinct records and checks append-only Git history.

The generic boundary does not inspect arbitrary tool destinations. A fresh
approval of an injected BCC can pass it, as can an exact replay with a fresh
approval or an HTTP argument URL differing from the declared resource. The
host adapters add explicit target resolution and one-use claims. None of the
project-authored fixtures proves honest labels, outside adoption, provider
delivery, durable storage, or a barrier against unwrapped callback paths.
