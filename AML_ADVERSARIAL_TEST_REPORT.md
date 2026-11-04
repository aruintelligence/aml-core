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
