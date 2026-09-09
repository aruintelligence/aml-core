# ĀML Proof Map

**Status: SHIPPED**

Use this map when evaluating a public AML claim. Start with the claim, then follow the shortest available path to the implementation, test, or runnable proof.

| Public statement | Fast proof | Deeper evidence |
| --- | --- | --- |
| AML can ALLOW and SUPPRESS declared interface output | `docs/proof.html` | `scripts/check-flood-fixtures.js` |
| The same fixed execution can reproduce the same receipt | `demos/undeniable-proof/replay-proof.mjs` | CI deterministic replay gate |
| AML can sit in front of existing HTML | `docs/aml-gate-demo.html` | `docs/aml-gate.js` |
| AML can gate annotated existing DOM | `docs/dom-gate-demo.html` | `docs/aml-dom-gate.js` |
| AML can reject undeclared output inside an opt-in strict region | `docs/strict-zone-demo.html` | `<aml-zone mode="strict">` implementation |
| Browser evidence can detect mutation | `docs/browser-evidence-demo.html` | `docs/aml-browser-integrity.js` |
| Verification can happen away from the producing page | `docs/detached-verifier.html` | Python and Go reference verifiers |
| AML has a stable verifier target | `docs/verifier-contract.html` | immutable verifier snapshot + drift CI |
| AML publishes claim-bounded public literature | `PUBLICATIONS.md` | `library/` + `claims.json` |

## Fast skeptical path

1. Open the public proof.
2. Change one declared value.
3. Copy the exact proof URL.
4. Reproduce the receipt locally.
5. Tamper with evidence and verify rejection.
6. Run the black-box verifier harness.
7. Read `CLAIMS.md` before repeating a broad claim.

A failed reproduction is useful evidence. File it.
