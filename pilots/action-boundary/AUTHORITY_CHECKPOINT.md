# Detect an older local authority snapshot

The file authority can use an **opt-in checkpoint outside its own directory**. A host-owned synchronous compare-and-swap anchor records a store ID, sequence, and hash-chain head before each grant issuance, issuer revocation, or one-use claim. Newly initialized stores use checkpoint protocol 3, which also commits to a canonical digest of every grant, issuer epoch, operation marker, spent-claim record, and the authority mode record. The authority writes its local checkpoint only after the corresponding local records are durable and match that digest. A fresh instance fails closed if a retained outside checkpoint disagrees with either the local checkpoint or the committed state.

```js
import { createFileAuthorityAnchor, createFileRevocationHandoff } from
  "./file-revocation-handoff.mjs";

// Separate from the authority directory and its backup/restore domain.
const anchor = createFileAuthorityAnchor({ directory: trustedIndependentAnchorPath });
const authority = createFileRevocationHandoff({
  directory: trustedAuthorityPath, anchor
});
```

The file anchor is a **one-machine example**. It uses an owner-only directory, an exclusive local lock, and synced atomic file replacement. A host can supply its own `{ read, compareAndSwap }` object with the same synchronous, durable, strongly consistent behavior and support for `aml-file-authority-checkpoint/3` records. Every participating worker must use the same anchor and authority directory. Anchored mode starts only with an empty authority; it will not invent a trustworthy history for an existing unanchored store. An anchored store rejects callers that omit the anchor.

Protocols 2 and 3 scan the four decision-file namespaces in a fixed order, sort their filenames, canonicalize each parsed JSON record, hash the individual records, and commit the ordered list's digest to both checkpoints. Protocol 3 appends the canonical hash of `authority-mode.json` to that list. A valid but substituted weaker mode now disagrees with the independent checkpoint before a worker issues or dispatches. An unexpected filename, partial temporary record, missing record, or changed committed value stops the authority. Validation scans the decision files on startup and at the authority boundary; its cost grows with retained records. The host clock and post-callback outcome records are outside this commitment and retain their prior handling.

Protocol-1 and protocol-2 checkpoints with an established authority mode record remain readable and keep their original verification semantics. Protocol 1 detects **whole-directory rollback**; protocol 2 commits to decision files but leaves the mode record outside its digest. They do not silently gain protocol-3 protection or change protocol during a write. A pre-mode store without that record fails closed and requires operator reconciliation and migration; it cannot silently adopt a mode. Starting a new protocol-3 authority requires a fresh empty local directory and a fresh independent anchor after the host has reconciled any earlier operations; copying an old store into one is not a migration procedure.

The separately supported `claimOnce` hook can be configured at the same time. Choose that combined mode when initializing the authority; adding or removing the hook on an existing store fails its mode check and needs an explicit reconciled migration. It guards the spent host operation with an atomic external insert, while this checkpoint also records issuance and revocation transitions. Both configured mechanisms must permit dispatch before its callback runs. A checkpoint mismatch after an awaited external claim stops the callback and requires reconciliation.

The separate `epochAnchor` option uses an epoch-aware external claim at handoff and an asynchronous revocation protocol. It cannot be configured alongside this checkpoint; choose one revocation protection for an authority directory. The epoch-aware claim checks the held issuer epoch at dispatch. Protocol-3 checkpoints detect selective changes to the local epoch, other committed decision records, and mode before issuing or dispatching, provided the outside checkpoint remains current.

| Local operation | Ordering before an external effect |
| --- | --- |
| Issue a grant | Commit the expected decision-file digest to the anchor, write operation marker and grant, verify files, then write local checkpoint. |
| Revoke an issuer | Commit the expected digest to the anchor, write new epoch, verify files, then write local checkpoint. |
| Claim a grant | Commit the expected digest to the anchor, write spent marker, verify files, write local checkpoint, then invoke callback synchronously. |

If the anchor refuses an advance, the local mutation and callback do not run. If the anchor advances but a later local write fails or the process crashes, the two checkpoints disagree and subsequent work stops for operator reconciliation. This favors a missed action over replay. Never automatically copy the outside value into the local checkpoint, remove a crashed lock, or grant a new operation ID to resolve a mismatch. Check the provider's records, local grants and claims, and backup history first.

The protocol-3 check detects a **whole-directory rollback or selective change to committed decisions or mode** while its independent anchor remains current. It does not help if both copies are restored together, if the same actor can rewrite both stores, if clock or outcome records are changed, or if a tool bypasses this authority. The local file anchor shares the process's OS identity and is neither a multi-machine consensus system nor a trusted external witness. Its hashes authenticate neither the provider nor the approving person. A successful callback result still does not prove delivery. Production needs an anchor with an independently controlled retention and restore boundary plus a reviewed recovery procedure.

## Inspect before reconciliation

The read-only inspection command reports the pinned authority mode, observed authority lock and file-anchor lock, local and external checkpoint records, their agreement, and the protocol-2 or protocol-3 committed-state digest and decision-file counts:

```sh
node pilots/action-boundary/inspect-file-authority.mjs \
  /absolute/private/authority /absolute/independent/anchor
```

The optional second argument is the file anchor directory. The command opens it with `create: false`; it never creates a missing anchor or authority directory. It exits zero for `observed_consistent` and 2 for a lock, mismatch, unreadable state, or other `needs_reconciliation` result. A present authority or anchor lock might belong to a live worker or a crashed one. `checkpoints.comparison` distinguishes a local/external mismatch; `committed_state.comparison` distinguishes a protocol-2 or protocol-3 state mismatch while the checkpoints still agree. `committed_state.includes_authority_mode` is true only for protocol 3. Protocol 1 reports `not_committed`, not a successful state verification. Omit the anchor only to inspect an unanchored store; an anchored local checkpoint without its anchor reports `authority_anchor_not_supplied`.

`reconciliation` lists claimed grants with no local outcome or an `outcome_unknown` record, even if the lock is gone and the checkpoints agree. Each candidate has only a grant ID and opaque operation/idempotency hashes for looking up the host's external claim and provider history; it does not include the prepared request or recipient. It also scans all grants and operation markers, including unspent ones: an orphan operation marker can block reuse of a host intent, and a missing or mismatched marker can make an unspent grant unusable. These links, malformed grant and operation records, and missing or mismatched claim and outcome links produce `invalid_records` and require reconciliation. An outcome must use one of the writer's valid status/reason pairs: `returned`/`callback_returned` or `outcome_unknown`/`callback_error`. An invalid pair requires reconciliation rather than counting a local return. `returned` counts callbacks that returned locally; it is not a delivery count. A missing outcome does not prove the callback ran: the external claim could have rejected or the worker could have stopped before handoff. These candidates require human review, never automatic retry.

The inspector also validates each present issuer epoch against its filename and checks the local clock record for an invalid shape, unreadable bytes, or an uncertain temporary write. It reports a missing clock when grants, operation markers, or claims exist; issuing a grant writes the clock first. These checks also apply to unanchored stores, where there is no committed-state digest. A well-formed clock value is an observation only: without an independent clock witness, the inspector cannot detect a valid-looking rollback or establish the true time.

The command performs no unlock, mode initialization, checkpoint advance, grant issue, clock update, provider call, or recovery. A missing mode reports `authority_mode_missing`, including in an empty directory: a never initialized store cannot be distinguished from one whose mode was deleted. Its scan is not an atomic snapshot of live workers, and `observed_consistent` cannot establish provider delivery, an independently protected anchor or external claim backend, or permission to resume an uncertain operation. Preserve the records and reconcile the provider's operation and idempotency history before any operator-controlled recovery. `inspectFileRevocationHandoff({ directory, anchor })` exposes the same observation to a host without invoking the CLI.

## Cross-check a stopped protocol-3 store in Python

For a separate implementation of the commitment check, take **quiescent copies** of the local authority and its separately retained file anchor, preserving ownership and owner-only permissions. Then run the project-authored Python verifier:

```sh
python3 pilots/action-boundary/verify_authority_checkpoint.py \
  /path/to/authority-copy /path/to/anchor-copy
```

It exits 0 and prints JSON with `status: "consistent"`, the store ID, sequence, state digest, and counts only if the two checkpoint records agree and the four decision-file collections plus mode recompute to that digest. It also checks the generated record shapes, grant/operation/claim links, private file permissions, uncertain temporary entries, and authority locks. A nonzero exit prints `status: "inconsistent"` and a reason such as `anchor_mismatch`, `state_mismatch`, or `unexpected_state_entry`. It rejects protocol 1 and 2 explicitly: their commitments do not cover the same state. The verifier does not create an authority, advance a checkpoint, or call a provider.

This check assumes no writer is active while the copies are taken. Its result covers the current committed records, not the historical chain leading to the checkpoint head or the outcome files. `consistent` does not clear a claim listed in the JavaScript inspector's `reconciliation` report; review provider history for those candidates. A matching but jointly restored or jointly rewritten authority and anchor can pass. This is a second, project-authored implementation of the protocol-3 snapshot check, not an independent witness, audit of the host, or proof of a provider effect. Keep the original stores and provider records for reconciliation after any failure; do not repair by copying one checkpoint over the other.

Run the project-authored child-process and failure tests:

```sh
node --test test/action-boundary-file-authority-anchor.test.js \
  test/action-boundary-file-authority-inspection.test.js \
  test/action-boundary-checkpoint-verifier.test.js
```
