# Separate-process SQLite provider fixture

An omitted execution-gate path on `request` fails closed before opening the
database. Historical ungated comparisons require the explicit
`--diagnostic-only-unguarded` argument and label their response
`diagnostic_only_unguarded: true`. That mode still writes a synthetic row;
never expose it as a protected provider route.

Run `node --test test/action-boundary-sqlite-provider-fixture.test.js` with Python 3. The test launches a separate Python process for each request and status query. Its only side effect is one unique row in a temporary provider SQLite database. The host process cannot infer a result from the child's missing acknowledgment; a later read-only query checks the provider record by stable host operation ID.

The provider hashes exact received request bytes, persists one `(operation_id, request_sha256, destination, effect_id)` row under a SQLite unique key, and returns the original effect ID for a duplicate identical request. A changed payload or destination under the same operation ID is rejected. `before_commit` exits without an effect row; `after_commit` commits the row and exits without an acknowledgment. Both initially look like an unknown outcome to the caller. Only a subsequent status read distinguishes them **within this fixture's complete database-view assumption**.

This is an experimental provider component. The separate coordinator/host composition and an optional local signing wrapper are documented in `COORDINATOR_PROVIDER_EXPERIMENT.md`. A provider row is provider-reported completion of this artificial effect; it is not independently observed physical delivery. The base SQLite fixture does not authenticate status responses or sign evidence. Its optional signer has a key readable by the same local identity as the host, and cannot establish independent provenance or protect against a same-identity DB rewrite or rollback. Neither fixture uses a persistent network service or proves no unobserved real-world effect. No automatic retry is made by the host-restart experiment. Do not use this fixture for actual email, payment or deletion.
