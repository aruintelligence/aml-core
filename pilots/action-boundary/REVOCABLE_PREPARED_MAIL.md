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
  getPolicy: () => hostCurrentExactPolicy(),
  prepare: (toolArgs, context) => hostBuildProviderRequest(toolArgs, context),
  requestApproval: ({ proposal, proposal_sha256 }, context) =>
    hostAuthenticateAndReview(proposal, proposal_sha256, context),
  execute: (frozenRequest, { idempotencyKey }) =>
    hostMailer.startSend(frozenRequest, { idempotencyKey })
});

const outcome = await send(modelMailArguments, hostContext);
// A host revocation route calls authority.revokeIssuer({ tenant: "tenant-a", issuer: "mail-host" }).
```

The policy must have one exact `send_message` / `send` rule for the **prepared** To/CC/BCC manifest with `requires_approval: true`. The approval callback must authenticate its approver and return `{ approved: true, proposal_sha256 }` for the shown proposal. The digest includes the prepared subject and body. The host must construct its policy and identifiers independently of tool arguments. `execute` receives only the frozen prepared request and a stable idempotency key; it must submit exactly those fields and begin the actual provider handoff synchronously. A callback that merely schedules an asynchronous send reopens a revocation window.

| Boundary step | Fail-closed behavior |
| --- | --- |
| Snapshot tool arguments; prepare and validate five-field request | Unknown delivery fields or invalid recipients throw before approval or callback. |
| Evaluate exact policy; observe issuer epoch | Missing/ambiguous rule or unavailable authority blocks before approval. |
| Await authenticated approval for the prepared proposal | Missing or mismatched digest blocks. No grant has been issued yet. |
| Re-read policy; issue grant only at observed epoch | Policy change or revocation during approval blocks; a newer epoch cannot silently reauthorize the old approval. |
| Locked claim and synchronous callback invocation | Revocation after issuance and before claim blocks. A replay blocks. A callback error remains an unknown, spent attempt. An optional external claim must commit before callback invocation. |

The returned `receipt.execution_status` is `blocked`, `dispatched`, or `unknown`, with `dispatch_count` from the authority. `dispatched` means the host callback returned, **not** provider acceptance or delivery. `unknown` must not trigger an automatic retry. An approval can remain pending indefinitely unless the host enforces its own approval timeout; the grant TTL starts at conditional issuance. A fresh action begun after revocation may be approved under the newer epoch because `revokeIssuer` invalidates old work, rather than suspending an issuer. Every policy revocation that must invalidate pending approvals must also advance the same issuer epoch.

The adapter does not authenticate a human, assess policy meaning, inspect the provider's actual routing, prevent another code path from sending, or coordinate machines. Use a private trusted local filesystem shared by all participating workers; the file store intentionally strands a crashed lock for operator reconciliation. For rollback defense on spent grants, the host can provide the authority an independently held atomic `claimOnce` hook, as described in [the file authority contract](README.md#anchor-a-one-use-claim-outside-the-local-authority-store). An asynchronous claim keeps the local lock busy and rechecks expiry before the callback; an uncertain claim consumes the local grant and never sends. The hook does not preserve issuer revocations for unspent grants after a store rollback. The included tests use an in-memory sender and a second Node process for revocation, not a live provider or outside audit.

```sh
node --test test/action-boundary-revocable-prepared-mail.test.js test/action-boundary-file-revocation-handoff.test.js
```
