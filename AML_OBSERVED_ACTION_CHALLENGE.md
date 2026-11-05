# Runner-observed local action challenge (experimental)

This optional challenge gives an outside implementation a real local callback to invoke. The runner starts a temporary server bound to `127.0.0.1` for each case. It passes `host.observed_callback: { url, token }` in the case JSON. The adapter must send one `POST` with the **frozen proposal** as its JSON body and the token in `x-aml-challenge-token` from inside its protected tool callback. The server records accepted requests and responds 200. For `host.tool: "throw"`, the adapter should throw after that local request to model an uncertain callback. It should still print the original `/1` plan, receipt, and self-reported fields to stdout for comparison.

Run from the repository root with Node 22 or later:

```sh
node scripts/run-action-observed-challenge.mjs --self-test
node scripts/run-action-observed-challenge.mjs --self-test --probes
node scripts/run-action-observed-challenge.mjs --probes -- node your-adapter.mjs
```

`--self-test` uses project-owned reference code and is E2 at most. The ordinary command runs an adapter supplied by the evaluator. `--case approved-send` scopes a run for debugging; `--probe-seed` accepts 32 lowercase hexadecimal characters when `--probes` is present. The runner writes `aml-action-observed-challenge-report/2` JSON to stdout and exits nonzero on a failed case. The legacy 13-case runner and its `/1` output contract remain unchanged.

The report distinguishes adapter-reported `tool_calls` from `observed_callback_count` and `observed_proposals`. A static adapter that claims a callback ran but never contacts the local endpoint fails. The 13 published cases and six generated probes check matching, denied, stale approval, mutated proposal, policy change, and uncertain callback outcomes. The report includes the probe seed and exact manifest/vector hashes so failures can be reproduced.

**Trust boundary:** the runner observes a request to a local service. It does not prove that the adapter's policy logic caused the request; an adversarial adapter can call the endpoint directly after reading the case JSON. The probes are project-defined and the input case IDs are not hidden. Source review, independently computed hashes, and an evaluator-owned provider integration remain necessary for independent implementation and external operation claims. No real email, payment, or third-party service is called. The loopback token is local test material, not a production authentication design.
