# Detect an older local authority snapshot

The file authority can now use an **opt-in checkpoint outside its own directory**. A host-owned synchronous compare-and-swap anchor records a store ID, sequence, and hash-chain head before each grant issuance, issuer revocation, or one-use claim. The authority writes its local checkpoint only after the corresponding local record is durable. A restored older authority directory therefore has a checkpoint that disagrees with the external anchor and fails closed on a fresh instance.

```js
import { createFileAuthorityAnchor, createFileRevocationHandoff } from
  "./file-revocation-handoff.mjs";

// Separate from the authority directory and its backup/restore domain.
const anchor = createFileAuthorityAnchor({ directory: trustedIndependentAnchorPath });
const authority = createFileRevocationHandoff({
  directory: trustedAuthorityPath, anchor
});
```

The file anchor is a **one-machine example**. It uses an owner-only directory, an exclusive local lock, and synced atomic file replacement. A host can supply its own `{ read, compareAndSwap }` object with the same synchronous, durable, strongly consistent behavior. Every participating worker must use the same anchor and authority directory. Anchored mode starts only with an empty authority; it will not invent a trustworthy history for an existing unanchored store. An anchored store rejects callers that omit the anchor.

The separately supported `claimOnce` hook can be configured at the same time. It guards the spent host operation with an atomic external insert, while this checkpoint also records issuance and revocation transitions. Both configured mechanisms must permit dispatch before its callback runs. A checkpoint mismatch after an awaited external claim stops the callback and requires reconciliation.

The separate `epochAnchor` option uses an epoch-aware external claim at handoff and an asynchronous revocation protocol. It cannot be configured alongside this checkpoint; choose one revocation protection for an authority directory. Unlike the checkpoint, `epochAnchor` can reject a selectively restored local issuer epoch at claim time. The checkpoint instead checks whether a whole authority directory is older than its retained outside state before issuing or dispatching.

| Local operation | Ordering before an external effect |
| --- | --- |
| Issue a grant | Advance anchor, write operation marker and grant, then write local checkpoint. |
| Revoke an issuer | Advance anchor, write new epoch, then write local checkpoint. |
| Claim a grant | Advance anchor, write spent marker, write local checkpoint, then invoke callback synchronously. |

If the anchor refuses an advance, the local mutation and callback do not run. If the anchor advances but a later local write fails or the process crashes, the two checkpoints disagree and subsequent work stops for operator reconciliation. This favors a missed action over replay. Never automatically copy the outside value into the local checkpoint, remove a crashed lock, or grant a new operation ID to resolve a mismatch. Check the provider's records, local grants and claims, and backup history first.

The bounded check detects restoration of the **whole authority directory** when its independent anchor remains newer. It does not help if both directories are restored together, if the anchor can be rolled back by the same actor, if a process with the same OS identity selectively changes records, or if a tool bypasses this authority. The local file anchor is not a multi-machine consensus system or a trusted external witness. Its hash chain authenticates neither the provider nor the approving person. A successful callback result still does not prove delivery. Production needs an anchor with an independently controlled retention and restore boundary plus a reviewed recovery procedure.

Run the project-authored child-process and failure tests:

```sh
node --test test/action-boundary-file-authority-anchor.test.js
```
