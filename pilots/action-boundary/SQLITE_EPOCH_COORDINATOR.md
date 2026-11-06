# SQLite epoch coordinator — controlled test prototype

Status: experimental, one-machine and project-authored. This reuses the existing `epochAnchor` interface of `file-revocation-handoff.mjs`; it does not replace the simple grant store wired into the connected MCP pilot. Python's standard-library SQLite client runs in a separate subprocess per decision. The database path is outside the local authority snapshot. Both processes and directories still run under the same OS identity in the tests, so this is **not** independent administration, a multi-host service, or production anti-rollback.

Run `node --test test/action-boundary-sqlite-epoch-coordinator.test.js`. Python 3 with `sqlite3` is required. The test creates private temporary directories, initializes a fresh coordinator, and deletes all fixture data afterward. No network, third-party account or external effect is used.

The coordinator accepts only the existing `aml-file-authority-external-claim/2` and `aml-file-authority-external-epoch/1` requests through the local adapter. Its `BEGIN IMMEDIATE` transaction obtains the one-writer decision domain; the conditional epoch check plus unique `claim_key` insertion or epoch update occurs inside that transaction. **COMMIT before the accepted response** is the linearization point for this fixture. The database uses `synchronous=FULL` and rollback-journal mode on the host filesystem; no power-loss test establishes its durability in a deployment. A second worker either observes a spent key or a changed epoch. SQLite's one-machine serialization is not distributed consensus.

| Case | Expected controlled outcome |
| --- | --- |
| Local authority snapshot restored; coordinator retained | Same grant blocked with zero additional callback. |
| Eight separate claim processes for one key | One accepted database insert. |
| Claim racing with epoch advance | A claim may win before revocation or fail after it; a stale claim cannot succeed afterward. |
| Revocation, then restore local unspent authority | Old epoch blocks callback. |
| Commit followed by lost acknowledgment | Caller sees no success response; retained claim rejects repeat. Host must reconcile, not infer a provider result. |
| Coordinator database unavailable | Host returns `indeterminate` and no callback. |
| **Both** authority and coordinator restored | Duplicate callback is possible. This preserved counterexample requires genuinely independent retention and access control. |

The fixture has no authenticated API, grant issuance in the coordinator, policy-decision proof, evidence signature, stable provider, request dispatch, provider-side idempotency, verifier, backup controls, tenant access isolation, database migration, or recovery operator workflow. Its `inspect` count is diagnostic, not an independently authenticated receipt. The host must protect the coordinator endpoint and database from the AI and keep the latter outside the authority's rollback/failure domain. A database copied and restored with the host store defeats the claimed protection; a malicious or bypassing host can invoke a provider anyway. Do not use this fixture to authorize real actions.
