# Detect a policy change that returns to identical bytes

An exact policy digest cannot reveal an unobserved sequence in which a rule is
revoked and restored before the next adapter call. In the local comparison,
the policy reads A at issuance and A at dispatch, so the original one-use
receipt invokes its callback once. This does not contradict the earlier
observed-revocation fix: no call was made while policy B was active.

The receipt-bound adapters now accept an optional host-owned `policyEpoch()`
function returning a nonnegative safe integer. The host increments that value
for **every** policy or destination-mapping change and persists it across
workers and restarts. The adapter includes the initial value in the signed
authorization receipt and checks it after approval and immediately before
dispatch. A changed or unavailable epoch suppresses the call and spends the
grant. Invalid initial values fail issuance. No-epoch integrations retain
their previous receipt bytes and behavior.

```js
const adapter = createEmailAdapter({
  provider: hostMailer,
  policy: () => hostPolicyStore.readPolicy(),
  policyEpoch: () => hostPolicyStore.readMonotonicEpoch(),
  secret: hostPrivateKey,
  authorize: hostApproval
});
```

The [four-adapter comparison report](../docs/action-receipt-policy-epoch-report.json)
includes exact proposals, policies, complete receipts and hashes. With no
epoch, a local A→B→A sequence yields four callbacks. With the epoch, the same
sequence yields zero callbacks; four approval-time sequences also suppress
issuance. Four unchanged-epoch controls dispatch normally. The four new
receipts append after all 504 prior rows in the
[registry](../registry/README.md).

```sh
node scripts/build-action-epoch-report.mjs --check
node --test test/action-receipt-adapters.test.js
node scripts/verify-action-receipt-registry.mjs --check
```

The epoch source in this report is an in-memory counter and the callbacks are
project-authored fakes. Production assurance depends on a durable, monotonic
epoch that advances with each relevant host change and cannot roll back. The
adapter cannot prove the host's epoch implementation or the external effect.
