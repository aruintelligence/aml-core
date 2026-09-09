# ĀML Claims Ledger

**Status: SHIPPED**

This ledger separates what ĀML can prove today from what remains a draft, specification direction, or pitch.

Public status labels:

- **SHIPPED** — implemented in this repository and linked to evidence.
- **SPEC** — documented contract or standards-oriented surface; not necessarily universally implemented.
- **DRAFT** — proposed material that may change.
- **PITCH** — positioning or future-facing use case, not evidence of adoption.

## SHIPPED claims

1. **ĀML can evaluate declared interface meaning before rendering.**  
   Evidence: `compiler/`, `runtime/interfaceFirewall.js`, `test/`.

2. **The public prototype rule can suppress or allow based on declared `restoration_value` and `attention_cost`.**  
   Evidence: `docs/proof.html`, `conformance/flood/`, `scripts/check-flood-fixtures.js`.

3. **The same fixed input can reproduce the same execution receipt.**  
   Evidence: `demos/undeniable-proof/replay-proof.mjs`, CI step `Prove deterministic receipt replay`.

4. **Browser evidence can detect mutation of bound receipt/evidence fields.**  
   Evidence: `docs/aml-browser-integrity.js`, `docs/aml-browser-evidence.js`, `docs/browser-evidence-demo.html`.

5. **A detached witness bundle can be verified without importing the page that produced it.**  
   Evidence: `docs/detached-verifier.html`, `independent/python/verify_witness.py`, `independent/go/main.go`.

6. **Python and Go reference verifiers are exercised through the same black-box verifier contract.**  
   Evidence: `scripts/run-verifier-conformance.mjs`, CI Python/Go conformance steps.

7. **ĀML publishes an immutable verifier-contract snapshot and rejects silent drift against it.**  
   Evidence: verifier contract snapshot files plus `scripts/check-verification-contract-drift.mjs`.

8. **ĀML publishes a numbered, machine-readable publication library.**  
   Evidence: `library/`, `library/catalog.json`, `scripts/check-library-surfaces.mjs`.

## Claims ĀML does not make

ĀML does **not** currently claim that:

- it is a ratified global standard;
- enterprises broadly use it in production;
- its declared scores objectively measure human cognition or wellbeing;
- an AML decision is automatically ethical, legally compliant, or factually correct;
- a cryptographic signature proves institutional legitimacy or truthful declared intent;
- reference implementations maintained by ĀRU count as independent external witnesses.

## Commercial and official identity

The MIT software license and official ĀML™ / ĀRU™ marks are separate. Technical conformance alone does not grant endorsement, partnership, certification, or official-brand rights.

Official/commercial inquiries: **Office@aruintelligence.com**
