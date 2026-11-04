# Host integration guide (experimental)

Start with the local function-tool example in `AML_AGENT_INTEGRATION_REFERENCE/README.md`. The host maps the actual provider arguments to a real target, supplies policy from trusted configuration, authenticates the human approval, and persists a one-use grant before calling `createGuardedToolExecute`. Neither model text nor MCP tool metadata supplies those trusted callbacks. For MCP, review `pilots/action-boundary/mcp-call-tool-gate.mjs` and its schema/target assumptions.

Keep a stable **host-generated operation ID** in a durable ledger in addition to the proposal digest. Use provider idempotency if contractually available, record provider request/acceptance/completion separately, and reconcile uncertain outcomes without blind retries. The local example does not combine the advanced revocation authority or a production provider. Do not expose the raw tool on a bypass path.

Run `node --test test/action-boundary-local-outbox.test.js` and inspect the `unknown` case before adapting a real side effect. Re-run the published vectors and the full suite against the pinned commit of any integration.
