# Adversarial test report — 2026-11-04

Source baseline: `79a24ba96820a4ca974bcba30b797bf35dd7abc7`. All tests are project-authored local tests (E2 at most).

| Scenario | Expected | Baseline observed | Branch observed | Regression |
| --- | --- | --- | --- | --- |
| Spent-marker directory lost; a fresh grant is issued; old grant replayed | No second successful consumption | **Fail:** first `true`, replay `true` in an isolated temporary directory | Issuance fails closed when the store is partial; no callback | `test/action-boundary-file-grant.test.js` |
| Store state marker removed while old grants remain | No silent new store | No marker existed | `grant_store_incomplete` | Same file |
| Inherited Object/Array `toJSON` hook | Canonical action bytes unchanged | **Fail:** canonical bytes changed to `{"rewritten":true}` | Node/browser canonical bytes unchanged | `test/canonical-json-strictness.test.js`, `pilots/action-boundary/boundary.test.mjs` |
| Array input owns a `map` method | Input method does not rewrite authorization | Old implementation called `value.map` | Direct index copy ignores it; malformed array extras retain the historical `sorted-json-v1` projection | `test/canonical-json-strictness.test.js` |
| Two processes race for one grant | One callback | Existing local demo passed | 9/9 focused grant tests passed | Existing race test retained |
| Changed resource, payload or policy during approval | Block or dispatch frozen bytes | Existing tests passed | Focused boundary test passed | Existing boundary tests retained |
| Malformed browser receipt array/hidden field | Verifier rejects, even when legacy digest collides | Existing test passed | One first full run failed after overstrict canonicalization; correction restored the original negative fixture, now focused 23/23 pass | `test/browser-packet-json-integrity.test.js` retained unchanged |

First full post-change test run: 1,096 pass, **one fail** out of 1,097. The failing test was investigated and the canonicalization change corrected. The final full-suite rerun passed **1,098/1,098**, zero fail/skipped. No third-party endpoint, provider or live deployment was attacked. Power-cut behavior, filesystem identity races, external anchor rollback, cross-machine consensus and independent reproduction remain untested.

## Follow-up: approval replay and evidence challenge — 2026-11-05

Threat model: an effectful MCP integration supplies a reusable digest approval but omits atomic consumption. With `requires_approval: true`, two calls of the same action both returned `dispatched` in a local pre-fix reproduction. This is a host configuration gap, not a bypass of a correctly configured one-use consumer. The connected SDK pilot now uses a local file grant store and strict gate constructor: in its `approval_replay` case, two attempts produce one child handler audit entry, a first `host_dispatch_returned` receipt, then `approval_reused_or_expired` and zero additional handler calls. Unit test: `test/mcp-call-tool-gate.test.js`. Remaining limits: the approval fixture does not authenticate a person, the direct `/1` boundary permits optional consumption, and local filesystem claims do not solve whole-store rollback or distributed coordination.

An assurance review of the published 13-case challenge found that the runner accepts self-reported callback counts and executed proposals. A lookup adapter can pass by returning public expected outputs without hashing, evaluating policy, or executing. The challenge documentation now limits a runner pass to fixture-output agreement; E4 requires source inspection and independent computation. Runner-owned local effect observation and fresh probes remain open.

A sparse array can also impose work proportional to its declared length inside canonicalization before the 65,536-byte serialized proposal cap is checked. A local probe of one million holes took about 45 ms on the review host before rejection. The guarded-tool and MCP ingress now pass an optional 65,536-element array limit to the canonicalizer, so an array larger than any valid proposal could contain is rejected before allocation or index traversal. Tests use a maximum-length sparse proxy and assert zero index checks and zero callbacks. This is a scoped mitigation; direct use of pinned `dispatchAction`, dense objects, deeply nested inputs, and arbitrary Proxy traps still need proactive resource budgets. No throughput or cross-runtime guarantee follows from the single timing probe.
