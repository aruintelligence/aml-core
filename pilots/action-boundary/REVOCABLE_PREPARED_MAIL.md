# Connect a prepared mail request to revocable authority

`createRevocablePreparedMailToolExecute` composes the narrow prepared-mail schema and exact recipient policy with the file-backed, one-machine authority store. The host supplies identity, current policy, authenticated approval, provider request preparation, and the send callback. The model supplies only mail tool arguments.

```js
import { createFileRevocationHandoff } from "./file-revocation-handoff.mjs";
import { createRevocablePreparedMailToolExecute } from "./revocable-prepared-mail-tool.mjs";

const authority = createFileRevocationHandoff({ directory: privateLocalDirectory });
const send = createRevocablePreparedMailToolExecute({
  authority,
  tenant: "tenant-a", issuer: "mail-host", actor: "reviewer-42",
  audience: "mail-provider", purpose: "Send release notice",
  operationIdFor: context => context.hostPersistedOperationId,
  getPolicy: () => hostCurrentExactPolicy(),
  prepare: (toolArgs, context) => hostBuildProviderRequest(toolArgs, context),
  requestApproval: ({ proposal, proposal_sha256 }, context) =>
    hostAuthenticateAndReview(proposal, proposal_sha256, context),
  execute: (frozenRequest, { idempotencyKey }) =>
    hostMailer.startSend(frozenRequest, { idempotencyKey })
});

const outcome = await send(modelMailArguments, hostContext);
// A host revocation route calls authority.revokeIssuer({ tenant: "tenant-a", issuer: "mail-host" }).
// With an epochAnchor configured, it instead awaits authority.revokeIssuerAnchored(...).
```

The policy must have one exact `send_message` / `send` rule for the **prepared** To/CC/BCC manifest with `requires_approval: true`. The approval callback must authenticate its approver and return `{ approved: true, proposal_sha256 }` for the shown proposal. The digest includes the prepared subject and body. The host must construct its policy and identifiers independently of tool arguments. `operationIdFor` must synchronously return a stable, host-generated ID for this intended send; persist it across worker restarts and retries. Never derive the ID from the model's tool arguments or the proposal digest. A genuinely distinct send of the same content needs a distinct ID and a new approval. `execute` receives only the frozen prepared request and a stable idempotency key; it must submit exactly those fields and begin the actual provider handoff synchronously. A callback that merely schedules an asynchronous send reopens a revocation window.

| Boundary step | Fail-closed behavior |
| --- | --- |
| Snapshot tool arguments; prepare and validate five-field request | Unknown delivery fields or invalid recipients throw before approval or callback. |
| Evaluate exact policy; observe issuer epoch | Missing/ambiguous rule or unavailable authority blocks before approval. |
| Await authenticated approval for the prepared proposal | Missing or mismatched digest blocks. No grant has been issued yet. |
| Re-read policy; issue grant only at observed epoch and for an unspent operation ID | Policy change or revocation during approval blocks. A second attempt with the same ID cannot mint a new grant, even with another matching approval. |
| Locked claim and synchronous callback invocation | Revocation after issuance and before claim blocks. A replay blocks. A callback error remains an unknown, spent attempt. An optional external claim must commit before callback invocation. |

The returned `receipt.execution_status` is `blocked`, `dispatched`, or `unknown`, with `dispatch_count` from the authority. `dispatched` means the host callback returned, **not** provider acceptance or delivery. `unknown` must not trigger an automatic retry. A repeated ID blocks with `operation_already_claimed`; a changed prepared request or policy under that ID blocks with `operation_payload_mismatch`. The operation is spent **before** its grant is written. An error or crash in that gap can lose a send, so investigate the provider and local records before authorizing a genuinely new operation ID. The operation record does not expire with the short-lived grant and must not be automatically deleted. An approval can remain pending indefinitely unless the host enforces its own approval timeout; the grant TTL starts at conditional issuance. A fresh action begun after revocation may be approved under the newer epoch because `revokeIssuer` invalidates old work, rather than suspending an issuer. Every policy revocation that must invalidate pending approvals must also advance the same issuer epoch.

The adapter does not authenticate a human, assess policy meaning, inspect the provider's actual routing, prevent another code path from sending, or coordinate machines. Use a private trusted local filesystem shared by all participating workers; the file store intentionally strands a crashed lock for operator reconciliation. Its one-operation property depends on preserving that store unless the host supplies an independently held atomic `claimOnce` hook, as described in [the file authority contract](README.md#anchor-a-one-use-claim-outside-the-local-authority-store), or enables the [independent checkpoint](AUTHORITY_CHECKPOINT.md). The hook uses the stable host operation key to reject a new grant for a spent intent after local rollback. To preserve issuer revocation against old *unspent* grants, use either the [`epochAnchor` contract](README.md#preserve-issuer-revocation-across-local-rollback) and route every revocation through `await authority.revokeIssuerAnchored(...)`, or the checkpoint with its separately retained state; the two options cannot be configured together. An asynchronous claim keeps the local lock busy and rechecks expiry before the callback; an uncertain claim consumes the local grant and never sends. The included tests use an in-memory sender and separate Node processes for revocation and duplicate operation claims, not a live provider or outside audit.

```sh
node --test test/action-boundary-revocable-prepared-mail.test.js test/action-boundary-file-revocation-handoff.test.js
```
