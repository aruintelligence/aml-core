# Local integration test report

Command: `node --test test/action-boundary-local-outbox.test.js` or `node AML_AGENT_INTEGRATION_REFERENCE/local-outbox.mjs`.

Observed 2026-11-04: **1/1 test pass**. Deny → blocked/no append; changed payload → blocked/no append; approved → callback returned/one append; replayed grant → blocked/no additional append; callback error after append → unknown/two total local records. The checked-in `AML_AGENT_INTEGRATION_REFERENCE/report.json` records the deterministic receipts and local file hash. This is a project-authored local file side effect, not provider acceptance or an external pilot.
