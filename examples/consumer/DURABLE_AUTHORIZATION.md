# Durable authorization for a local action

Use the host-owned capability authorizer when exactly one retained local store
can serve every executor for an action. The host configures a trusted issuer
key fingerprint, audience and durable store at startup. It derives the subject
and session from its authenticated context, chooses the capability for the
route, and hashes the exact bytes it will send to the destination.

From the repository checkout, run the payment-request ledger example with
Node.js:

```bash
node examples/consumer/durable-authorization.mjs
```

Docker invocation from the same checkout:

```bash
docker run --rm --network none -v "$PWD:/app:ro" -w /app node:24-bookworm \
  node examples/consumer/durable-authorization.mjs
```

The example generates an ephemeral issuer and uses a temporary local store.
It expects one recorded payment request and denials for missing authorization,
expiry, changed request bytes, and replay after reopening the authority. It
records a local line and performs no transfer.

## Host contract

- At startup, call `openDurableConsumptionStore` with the operator-selected
  directory, then pass it to `createDurableCapabilityAuthorizer`. Every
  executor for the profile must use the same retained directory. Keep it
  outside agent control and ephemeral deployment storage.
- Pass only host-resolved bindings at invocation. Dispatch the exact hashed
  bytes only when the decision returns `authorized: true`. The decision's
  `valid` field is a signature-verification precondition.
- The profile always requires an issuer pin and durable consumption. If the
  host supplies an evaluated trust config, the issuer must satisfy it too.
  Recreate the host authorizer when refreshing the trust configuration.
- On local storage failure, deny dispatch. After a lost response or crash,
  reconcile using the operation ID and destination status. A consumed permit
  can remain spent even when no destination effect occurred.
- The guarantee applies to one retained filesystem store with working exclusive
  creation and sync. Restore or cloning the state creates a different recovery
  problem. This profile does not transact a remote effect with the local store.
  Use destination-side idempotency and independently evidenced status where
  required. See the [SQLite provider fixture](../../pilots/action-boundary/ACTION_CONTRACT_PILOT_003.md)
  for the separate case where the provider owns both writes in one transaction.

## Recover a destination outcome

On a POSIX system with Python 3 and the `cryptography` package installed, run:

```bash
node examples/consumer/recover-payment-request.mjs
```

A Python destination commits the request to SQLite under a unique operation ID.
The fixture sends itself SIGKILL immediately after commit, before it can
acknowledge the request. A fresh process reads status using a read-only
database connection and returns a signed receipt. The harness also injects
SIGKILL before commit on a different operation. That lookup returns no
receipt, so the host leaves the outcome unresolved. Both permits remain spent. The destination
signs the operation ID, stored request digest, destination, outcome, and
protocol version using its own Ed25519 key. The JavaScript verifier checks
those fields against the expected request and verifies the signature with the
destination public key supplied by the harness. It also confirms that the
authorization issuer's key cannot authenticate the outcome.

The example verifies two distinct forms of replay protection. The original
permit cannot be consumed twice, and a freshly authorized permit for the same
operation and request bytes leaves the same destination row. The harness sends
that second request deliberately to check destination idempotency. Recovery
itself is read-only.

The destination and host use separate processes and keys under one local OS
identity. In a deployment, the verifier needs the destination key through a
trusted channel and the destination must control its own writes and signing
key. This sandbox records a payment request only. A valid receipt attests to
the destination's claim that the request was recorded. These checks cover abrupt process termination at two SQLite transaction
boundaries. Network partitions, power failure, rollback, and production key
custody need separate validation.

To check a receipt offline, pass an existing directory to the recovery example.
It writes a fresh subdirectory with the receipt, exact request bytes, and
sandbox public key. Use the operation ID printed in the receipt for this demo.

```bash
node examples/consumer/recover-payment-request.mjs /tmp
node examples/consumer/verify-payment-receipt.mjs RECEIPT REQUEST OPERATION_ID DESTINATION_PUBLIC_PEM
```

For an external audit, supply the expected operation ID and exact request
bytes from your operation record. Obtain the destination public key from
your trusted configuration. The command verifies destination evidence
without querying the destination and reports no execution authority.
