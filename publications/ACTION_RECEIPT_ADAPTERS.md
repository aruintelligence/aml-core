# Four host-owned action adapters

Minimal working adapters wrap email send, HTTP request, database write, and UI
text render. The host constructs a proposal, owns the exact policy and private
HMAC key, issues a pre-dispatch authorization receipt, and presents that receipt
with the same proposal to the adapter. The adapter verifies the receipt hash,
host MAC, original one-use nonce, frozen proposal digest, current policy digest,
and resolved destination before invoking its provider callback.

An email adapter binds To, CC, and BCC as a single recipient resource. HTTP
binds the exact HTTPS URL and uses `redirect: 'manual'`. Database binds the
table and key. UI binds the root selector and renders text rather than HTML.
Each adapter passes a copy of frozen arguments to the provider. Unrecognized
argument fields, changed destinations, changed payloads, missing or edited
receipts, exact replay, and host policy revocation all suppress the callback.

```js
import { createEmailAdapter, mailResource } from './pilots/action-boundary/receipt-adapters.mjs';

const args = { to: 'team@example.test', cc: [], bcc: [], subject: 'Update', body: 'Ready' };
const proposal = { protocol: 'aml-proposed-action/1', tool: 'send_email', effect: 'send',
  resource: mailResource(args), purpose: 'Authorized update', arguments: args };
const adapter = createEmailAdapter({ provider: hostMailer,
  policy: () => hostPolicy, secret: hostPrivateKey,
  authorize: hostApprovalCallback });
const receipt = await adapter.issue(proposal);
const outcome = await adapter.dispatch(receipt, proposal);
```

The [machine report](../docs/action-receipt-adapters-report.json) publishes
the exact proposal, policy, full authorization receipt, SHA-256, eight observed
paths, and before/after callback counts for each adapter. In these local
fixtures, the four callback counts go from 0 to 4; 28 blocked variants produce
zero calls. Reproduce:

```sh
node scripts/build-action-receipt-adapters-report.mjs --check
node --test test/action-receipt-adapters.test.js
```

The report uses a public deterministic test key and simulated provider
callbacks; it proves local callback gating, not real mail delivery, HTTP
completion, database durability, or an actual browser render. A production
host must keep the key private, store one-use grants durably across processes,
and remove every unwrapped route to the provider. A thrown callback yields
`UNKNOWN` because the effect may have occurred; it is not retried automatically.

The [revocation follow-up](ACTION_RECEIPT_REVOCATION.md) adds separate,
append-only evidence for policy restoration and approval-time changes without
rewriting this original eight-path report.
