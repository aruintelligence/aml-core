# Product architecture and evidence boundary

ĀML has three candidate commercial surfaces. This is a product map, not three released enterprise products.

| Surface | Implemented reference | Potential buyer problem | Production gap |
| --- | --- | --- | --- |
| Action Boundary | Host-owned `planAction`/`dispatchAction`, target and function-tool adapters, local grants, MCP and revocation pilots under `pilots/action-boundary/` | Control exact autonomous tool actions and retain auditable decisions | Identity, distributed transaction store, provider handoff/reconciliation, bypass inventory and external pilot |
| Interface Governance | Compiler, policy engine, interface firewall, accountable decisions, browser/React examples in stable v1.3 and RC2 preview | Inspect and enforce declared meaning of generated UI | Customer-specific policy validity, accessibility testing, operational integration |
| Evidence Infrastructure | Hash-chained audit/receipts, signatures and reference verifiers in existing repository | Retain evidence for AI decisions and runtime changes | External trust roots, production retention, independent verifier and provider completion evidence |

The cross-cutting host contract is proposal → canonical snapshot → digest → policy → authenticated approval → atomic claim → controlled dispatch → bounded receipt. The last four steps must remain under host control; a model or tool-description string cannot authorize itself. For present status, use `AML_ENTERPRISE_CAPABILITY_MATRIX.md`, `RELEASE_NOTES_1.3.0.md`, `RELEASE_NOTES_1.4.0_RC2.md`, and `AML_EXECUTION_INTEGRITY_SPEC.md`. A digest is not a signature and a callback return is not delivery.
