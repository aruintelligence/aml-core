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

Run the project-authored child-process and failure tests:

```sh
node --test test/action-boundary-file-authority-anchor.test.js
```
