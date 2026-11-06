# Bounded model result

Command: `node scripts/check-action-authorization-model.mjs` on this work branch.

Observed on 2026-11-04: **PASS**, four approval-match combinations, 110 distinct reachable states, 182 explored transitions, four asserted invariants. This is a finite-state enumeration written and run by the project, not external formal verification or a theorem about deployment. It does not import or prove the production/pilot modules. See `AML_FORMAL_PROPERTIES.md` for assumptions and missing state dimensions.
