# Capability matrix — as inspected 2026-11-04

| Capability | Stable v1.3.0 | v1.4.0-rc.2 preview | Current `main` / this branch | Validation ceiling |
| --- | --- | --- | --- | --- |
| Compile/evaluate meaning-bearing UI and render decisions | Implemented | Carried forward | Implemented | Project tests (E2); policy meaning is not an objective human-outcome measure. |
| Signed policy packs, diffs, audit streams, accessibility/attention policies | Implemented per v1.3 release notes | Carried forward | Implemented | E2 on repository tests; no blanket accessibility certification. |
| Browser/front-end adoption, federated trust and extensive verifier surfaces | Some prototypes | Preview claims in RC2 notes | Present in source | Mixed per feature; check exact version and fixture. |
| Host-owned action plan/digest/dispatch reference | Not a v1.3 stable package promise | Not a stable RC2 promise | Experimental under `pilots/action-boundary/` | E2 local reference, not production. |
| One-machine grant, revocation and uncertain-operation pilots | Not stable | Not stable | Experimental, including this branch's A-01 fix | Local tests only. |
| Authenticated human approval and multi-host atomic authority | No | No | Host responsibility / design | NOT IMPLEMENTED by the reference. |
| Provider acceptance, completion and independent confirmation | No | No | Proposed execution-state contract | NOT VERIFIED. |
| External independent verifier/pilot/production | No evidence established here | No evidence established here | Challenge materials exist | No E3–E7 claim from this session. |

“Implemented” describes repository code and release notes, not operational fitness. The package metadata still reports `1.3.0`. Each buyer evaluation should pin a commit and separately test the required subset.
