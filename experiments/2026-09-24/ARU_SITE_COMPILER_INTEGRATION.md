# ĀRU site × ĀML browser compiler field experiment

**Date:** 2026-09-24  
**Owner:** ĀRU Intelligence Inc.  
**Classification:** Project-authored engineering experiment, not independent validation  
**Public UI:** https://aruintelligence.com/aml#gate-lab and https://aruintelligence.com/field-experiments  
**Base44 app:** `6a8837e92d6a3a0138ceeab5`  
**Source repository baseline:** `aruintelligence/aml-core@2fd09f6c214f943af471cabeceda67fab1b2d191`  
**Browser compiler source:** `docs/aml-browser.js`, GitHub blob `e4e64a00d20718c1b74d8e5dd9f9dd08b1b84865` (MIT)  
**Site before checkpoint:** `6ab4ce056a832bf1911dfaf7`, site commit `bcb71487548e71313e6ea6742100c1b51eaa169d`  
**Site integration checkpoint:** `6ab4cec89a3a59ff008b720f`, site commit `13695730daeca10034af24ab4f8d135e49211b57`  
**Final site checkpoint (PR link):** `6ab4d0385e097e2e2490dcf9`, site commit `2ff1f221f7cae96c354224cfd605672405aa14b7`

## Question and scope

Does the live ĀRU policy lab use the actual ĀML browser compiler to produce inspectable render decisions for declared example values? The previous `/aml` slider calculated `restoration >= attention` directly in a React memo. The intervention replaced that local calculation with a compiled `transmission` and recorded the originating source blob. It also made the scenarios and provenance visible in the field experiments area.

This experiment covers the public research lab, not every ARU page or an enterprise deployment. No visitor is scored, tracked by this experiment, or subjected to a suppression gate. The examples are synthetic declared inputs.

## Intervention and traceability

| Site path | Change | Reason |
| --- | --- | --- |
| `src/lib/aml-browser.js` | Vendored upstream `docs/aml-browser.js` verbatim after provenance header | Run the repository's actual browser lexer, parser, meaning tree, and render-decision path in the site |
| `src/lib/amlSiteExperiment.js` | Validated 0–10 finite declared inputs; generated a fixed `GateLab` transmission; extracted the compiler decision; exposed five scenarios | Keep site input boundaries explicit and reject invalid values |
| `src/pages/Aml.jsx` | Replaced local memoized inequality with `evaluateSiteCase`; clarified lab copy | Keep the slider's UI while using the canonical engine |
| `src/pages/FieldExperiments.jsx` | Added a compiler-backed scenario table, source blob and result/report links | Show evidence and limitations alongside the experiment |

The site adapter generates only numeric literals from finite, bounded values and uses constant strings for the ĀML source. This avoids interpolating visitor text into the compiler. The fixed scenario descriptions are illustrative and not estimates of cognitive effects. The browser compiler emits dynamic timestamps, so repeatability is asserted on inputs, decisions, and fallback flags, not timestamp equality.

## Reproduce

From this repository root:

```sh
node experiments/2026-09-24/verify-aru-site.mjs
```

The script imports `docs/aml-browser.js`, compiles each transmission, asserts that the declared inputs survive compilation, and checks both `render_allowed` and `fallback_triggered`. The site's `src/lib/amlSiteExperiment.js` uses the same browser module and scenario inputs. Its guard also rejected `-1`, `NaN`, and `11` in a separate Node check.

## Observed engineering results

| Scenario | Declared attention | Declared restoration | Expected | Observed |
| --- | ---: | ---: | --- | --- |
| Deep article | 3.2 | 9.1 | ALLOW | ALLOW |
| Focus reminder | 2.8 | 7.4 | ALLOW | ALLOW |
| Infinite scroll | 8.5 | 3.0 | SUPPRESS | SUPPRESS |
| Rage bait | 7.5 | 2.0 | SUPPRESS | SUPPRESS |
| Equality boundary | 4.0 | 4.0 | ALLOW | ALLOW |

**Sandbox checks on 2026-09-24:** five scenario decisions and three invalid-input guard checks passed; `npm run build && npx eslint src/pages/Aml.jsx src/pages/FieldExperiments.jsx src/lib/amlSiteExperiment.js src/lib/aml-browser.js` exited 0. Build printed an outdated Browserslist dataset advisory; it did not fail. The repository fixture script is supplied for independent rerun. These results are project-authored checks, not an external test report.

## Enterprise review boundaries and next gates

| Gate | Current evidence | Needed before wider deployment |
| --- | --- | --- |
| Source provenance | Exact upstream blob and before/after site checkpoints | Automate pinned upstream updates and review the diff before replacing the vendor copy |
| Policy repeatability | Five declared scenarios plus input guards | Expand conformance cases, version fixtures, and run CI against the site adapter |
| Safe failure | Adapter throws on malformed values or missing decision | Define and test a user-visible fallback for any production component that gates content |
| Accessibility | Existing slider has labels; this change retained the UI | Keyboard, screen reader, focus, contrast and mobile audit with recorded findings |
| Privacy and consent | This experiment sends no personal scores | Inventory any analytics and consent treatment separately before real visitor studies |
| Measurement | Compiler outputs and build checks only | Pre-register user study, accessibility and performance metrics before making benefit claims |
| Rollback | Before checkpoint ID above | Exercise rollback in a controlled preview and verify the public route after each release |
| Governance | Existing ĀML documentation and policy trail | Assign review owners and incident process for any actual suppression of production content |

No enterprise customer, Fortune 500 organization, clinical participant, independent auditor, or conversion study was involved. The ĀML rule uses declared values; it does not establish objective wellbeing or ethical correctness. This pilot verifies a bounded compiler integration, not universal behavior of the framework.
