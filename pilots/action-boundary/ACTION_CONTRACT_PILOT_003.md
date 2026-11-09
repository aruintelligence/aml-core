# Action Contract Pilot 003 — atomic provider-owned local effect

**Experimental, local fixture only. Not released, AVEP-certified, a new consensus
algorithm, a subjective-intent proof, or an exactly-once remote execution claim.**

## Question and bounded result

Can a provider that owns **both** authorization consumption and its entire effect
put them in one SQLite transaction, so process death does not strand a committed
claim without that effect? This pilot's effect is only a row in `effects`.
There is no payment, email, external API call, arbitrary SQL, callback, subprocess
effect or user-supplied executable action inside the transaction.

The new route uses the existing `aml-authorized-execution/1` signature profile,
including the exact request-byte digest and one immutable issuer-public-key
snapshot. It does not change the canonicalization/domain or the legacy
`consume(database, public_key, statement, signature, request_bytes)` API.

- `authorized_execution.consume_in_transaction(...)` requires a caller-owned
  active transaction, checks the signature/binding/pin/epoch/expiry/revocation,
  inserts the one-use claim, and **does not commit or roll back**.
- The new fixture owns `BEGIN IMMEDIATE`, fixed request validation, the effect
  insertion and `COMMIT`. Errors roll back the provisional claim and effect.
- Successful `COMMIT` is the local linearization point. A missing acknowledgment
  is not proof of failure. A repeat request is rejected, not reported as a new
  successful dispatch; recovery is a separate read-only operation.

The existing [two-database signed route](authorized-provider-fixture.py),
[Proof 002](VERIFIED_EXECUTION_RESEARCH_PROOF_002.md),
[gate counterexamples](../../test/action-boundary-execution-gate.test.js), and
[signed-authorization counterexamples](../../test/action-boundary-authorized-execution.test.js)
remain unchanged. Their claim-before-effect liveness loss still exists. The new
transaction is a conventional provider-owned control, **not** a fix for remote
services that cannot transact their effect with this database.

## Trust boundary and assumptions

The provider administrator, not an AI agent, selects the database path, pinned
issuer key, CLI command and optional test failpoint. The issuer private key is
not present at the provider. The agent supplies only the strict JSON envelope.
The issuer attests named principal/policy metadata; this fixture does not
independently authenticate a human, evaluate AML policy or prove comprehension.

All effectful request routes must use this transaction. The provider must retain
its database (claims, effects, revocations, configuration) and protect direct
writes and backups from the agent. A separate local process/directory does not
establish different administrative ownership. Tests run under one OS identity;
they do **not** demonstrate hostile-host isolation or multi-host operation.

SQLite's local filesystem locking/journaling and `synchronous=FULL` are assumed.
Tests use abrupt process exits, not power-cut, faulty-storage, network-filesystem
or multi-region fault injection. Local wall-clock expiry, issuer/provider
compromise, initial trust-root substitution and global/offline revocation remain
limitations. A retained committed effect remains reported after later revocation;
revocation is not an undo operation.

Expiry is sampled at the authorization check **after obtaining the writer lock**,
not a completion/COMMIT deadline. A scheduling pause after that check can allow a
commit after expiry. Revocation committed before admission blocks a waiting writer;
revocation queued behind an admitted writer does not cancel it. No hard real-time
clock/commit guarantee is provided.

One-use is scoped to **one retained database**, not to an issuer key globally.
Two independent stores with the same issuer pin each accept the same permit once.
There is no database-instance audience binding or distributed deduplication; do
not clone one authority into multiple active execution stores and claim global
at-most-once. The database path is a trusted ordinary filesystem filename, not a
caller-supplied SQLite URI. Shared URI opens encode literal `#`, `?`, `%`, spaces
and Unicode before appending a fixed read-only/existing-only mode. This corrects
URI confusion without making trusted-path selection or symlink races hostile-host
safe. Explicit initialization can create state; request/status do not create a
missing database or fall back to another filename.

## Files and compatibility

| File | Responsibility |
| --- | --- |
| `authorized_execution.py` | Shared immutable verification snapshot and transaction-scoped claim helper; legacy API still commits before return. |
| `atomic-authorized-provider-fixture.py` | Explicit admin initialization; one fixed local request effect; bound read-only status. |
| `../../test/action-boundary-atomic-authorized-execution.test.js` | Evaluator-owned persisted observations, crash/race/security tests, signature-profile vectors and negative controls. |
| `sqlite_path.py` | Shared ordinary-path URI encoding with fixed `ro`/`rw` modes, also used by relevant legacy authorization, gate, provider-status and witness-read helpers. |
| `../../test/action-boundary-atomic-review-regressions.test.js` | Node discovery/CI wrapper for the review-derived Python cases. |
| `../../test/fixtures/action-contract-pilot-003-review.py` | Author-integrated independent-review regressions, with defect reproductions changed to post-fix invariants; retained semantic-limit controls. |

No package dependency, install hook, stable export or existing protocol field is
added. Initialization is explicit: the shared authority tables are initialized
first, followed by the effect schema. A crash in cold schema initialization can
leave an incomplete store; request/status fail closed and do not repair it.

## CLI and restricted request

```text
python3 pilots/action-boundary/atomic-authorized-provider-fixture.py DB initialize ISSUER_PUBLIC_PEM
python3 pilots/action-boundary/atomic-authorized-provider-fixture.py DB request ISSUER_PUBLIC_PEM < envelope.json
python3 pilots/action-boundary/atomic-authorized-provider-fixture.py DB status < expected.json
```

Paths/commands are trusted provider-operator inputs, not agent-controlled fields.
An envelope has exactly `authorization`, `signature`, and `request_bytes`.
`request_bytes` is the exact UTF-8 JSON string covered by the signed SHA-256.
The existing authorization statement has its unchanged strict field set.

The parsed request has exactly:

```json
{
  "operation_id": "00000000-0000-4000-8000-000000000001",
  "destination": "fixture:atomic",
  "effect": "record:simulated",
  "body": { "value": "synthetic local record" }
}
```

`operation_id` must be a canonical lowercase UUID, the destination/effect are
fixed, and `body.value` is a string of at most 1,024 UTF-8 bytes. That string is
only data; it is not executed or interpreted as SQL. JSON duplicate keys and
nonfinite constants are rejected, and total stdin is capped at 65,536 bytes.
This is a small-profile bound, not protection against arbitrary hostile hosts
or all parser/CPU resource attacks. No untrusted input selects a failpoint.

For status, `expected.json` has exactly `operation_id`, `request_sha256` and
`destination`. Both tables are read in one read-only snapshot. A matching pair
returns `PROVIDER_REPORTED`, its exact record and
`independent_confirmation: false`. No pair returns `INCOMPLETE`/null, never
"failed", "undone", "safe to replay" or "no earlier execution". A partial,
conflicting or malformed history rejects rather than fabricating/repairing rows.
Status cannot silently create a missing database.

## Crash matrix and truthful recovery

Provider-operator-only `--fault=NAME` deliberately calls `os._exit`, bypassing
Python cleanup; it is a local test facility, never part of the agent envelope.

| Failpoint | Exit | Persisted state after fresh-process access | Recovery |
| --- | --- | --- | --- |
| `before_claim` | 80 | zero claims / zero effects | `INCOMPLETE`; no automatic retry |
| `after_claim` | 81 | zero claims / zero effects | provisional claim rolls back |
| `after_effect` | 82 | zero claims / zero effects | provisional effect and claim roll back |
| `before_commit` | 83 | zero claims / zero effects | no committed success |
| `after_commit` | 84 | one claim / one matching effect | `PROVIDER_REPORTED`; replay rejected |

The automated tests explicitly invoke a still-valid permit again after a known
pre-commit worker death to check that no stranded claim survives. The **status
function never makes that retry decision**. Its `INCOMPLETE` output alone is not
an authorization to retry, especially with an in-flight worker, provider history
loss, expired authority or a non-transactional remote effect.

Recovery reuses the existing
[state reducer](provider-execution-state.mjs),
[status signer](signed-provider-status.mjs), and
[status/history verification](verify-provider-status.mjs). The unchanged signer
can read the shared effect-row shape through the original read-only fixture
status route. A signed row authenticates a provider statement, **not** independent
observation or the atomic pair invariant; the new bound status and test-owned SQL
observations check that invariant. The reducer still accepts trusted host-supplied
labels. Tests promote uncertain to provider-reported completed, never to
independently confirmed.

## Adversarial acceptance and retained failures

The tests independently query persisted rows and bind operation ID, digest,
destination and effect ID; they do not trust self-reported dispatch counters.
Coverage includes:

- Abrupt death at all five failpoints and fresh-process recovery.
- Eight concurrent consumers: one success, seven spent rejections, one pair.
- Forged/mutated authorization and exact request, duplicate keys/nonfinite JSON,
  invalid schemas, unsupported effects and oversize inputs: no claim or effect.
- Revocation before execution blocks; revocation after commit preserves truthful
  committed history. Stale policy epochs and substituted keys reject.
- Same operation ID with a different **validly signed** body cannot receive replay
  success; status with its new digest rejects instead of showing old completion.
- Missing database/schema and partial/corrupt history fail closed without repair.
- Literal `#`, `?`, `%`, space and Unicode filenames retain all four tables in
  exactly the selected file; request/status and relevant legacy helpers neither
  split stores nor create alternate missing databases.
- The test signer matches the separate ASCII-escaped authorization profile for
  DEL, control characters, quotes/backslashes and safe-JavaScript integer vectors.
  Core sorted-json-v1 bytes remain distinct and wrong-profile signatures reject.
  The JS test helper rejects unsafe/fractional numbers; this is its narrower input
  domain, not a change to the Python verifier or core canonicalization.
- Review-derived tests exercise WAL crashes, waiting writer expiry/revocation,
  stale WAL snapshots, savepoints, cold initialization, SQL-looking literal data,
  UTF-8 byte boundaries, malformed stores and mutation of every authority field.
- Caller-owned transaction stays open; helper requires an active transaction,
  and its provisional claim is invisible to a separate reader until committed.

**Known negative controls are part of the acceptance suite:**

1. Restore the entire provider database to a pre-effect snapshot. The original
   unexpired authorization works again and produces a different effect ID.
   Retaining both signed histories yields `CONFLICTING_EVIDENCE`; the latest row
   alone conceals the earlier execution. This limitation is not fixed.
2. A provider administrator with direct SQL access can insert an ungated effect
   without any claim. The new bound status detects the inconsistent pair but
   cannot prevent that administrator's action or establish complete mediation.

3. Two retained databases with the same issuer pin each accept an identical valid
   envelope once. This records the per-store (not global) one-use boundary.
4. A local test harness scheduling delay after authorization admission can commit
   after expiry. The check is not a hard completion deadline.

Keep these failures when improving the system. A local SQLite row is not a
trustworthy observation of a real-world outcome, and neither signing nor this
transaction makes an honest provider out of a malicious one.

## Reproduction

No dependency installation is required; Node, Python 3 and OpenSSL must be
available. The project test runner is `node --test`, with no package install hooks.

```sh
node --test test/action-boundary-atomic-authorized-execution.test.js test/action-boundary-atomic-review-regressions.test.js
node --test test/action-boundary-authorized-execution.test.js test/action-boundary-execution-gate.test.js
node --test test/action-boundary-signed-provider-status.test.js test/action-boundary-local-provider-recovery.test.js
node --test test/action-boundary*.test.js
```

Run in a credential-free, network-isolated local environment. Test keys are
freshly generated synthetic keys in temporary directories, not production
credentials. No external provider, deployment, publication or customer contact
is needed or authorized by these examples. Record actual commands/results and
source revisions separately; a source assertion is not an executed test result.

## Review correction boundary

A separate bounded review of the original four-file candidate reproduced SQLite
filename URI confusion and a test-signing profile mismatch. This candidate encodes
all relevant SQLite file URIs and fixes only the test signer, without weakening
the verifier or changing core wire semantics. Original reproducer artifacts are
preserved outside the source tree; the integrated tests assert corrected behavior.
The author integrated and extended those tests. This is not a second independent
review, universal non-bypass proof, hostile-host audit, or new formal refinement
proof. Cloud CI and final separate-review clearance must be recorded separately.
