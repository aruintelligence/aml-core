# ĀML Security Evaluation Checklist

Use this checklist when deciding whether an ĀML evaluation is ready to move from prototype proof toward a controlled production decision.

Passing the reference demo, conformance fixtures, or repository CI does **not** by itself establish production security.

## 1. Scope the deployment

Record:

- exact application/service being evaluated;
- exact ĀML version or commit;
- policy/profile version;
- interface surfaces in scope;
- data classes involved;
- whether ĀML is advisory, shadow, canary, or enforcing;
- owners for application, security, policy, and incident response.

## 2. Authentication and authorization

Verify:

- callers are authenticated where required;
- authorization is enforced independently of interface rendering;
- capability boundaries cannot be expanded by untrusted interface content;
- administrative actions require appropriate privilege;
- signed capability/authorization artifacts are validated against the intended trust roots;
- revocation behavior is defined and tested.

Do not treat a render decision as an authorization decision unless the surrounding system explicitly and safely defines that contract.

## 3. Key and secret management

Verify:

- private signing material is not stored in public source control;
- production keys are generated and stored in an appropriate secret/key-management system;
- key rotation is documented;
- compromised-key response is documented;
- trust-root changes require controlled review;
- test/demo keys cannot be mistaken for production authorization.

## 4. Input trust boundaries

Identify every source of AML inputs, including:

- model output;
- application state;
- user input;
- remote policy/configuration;
- browser attributes;
- API requests;
- imported artifacts;
- third-party data.

Test malformed, missing, adversarial, oversized, stale, replayed, and contradictory inputs.

## 5. Policy integrity

Verify:

- the active policy/profile is explicit;
- policy changes are versioned;
- policy changes are reviewable;
- policy provenance is available;
- rollback is possible;
- unknown or unsupported policy versions fail in a defined manner;
- policy disagreement or dissent is visible where the deployment relies on consensus.

## 6. Receipt and evidence integrity

Test:

- deterministic replay where promised;
- receipt hash verification;
- signature verification where used;
- tamper rejection;
- canonicalization behavior;
- provenance links;
- replay protection where required;
- evidence retention and deletion policy;
- whether an independent verifier can reproduce the result without trusting the original page/process.

## 7. Network and service security

If using the HTTP/service surface, define and test:

- TLS termination;
- authentication;
- authorization;
- request-size limits;
- rate limits;
- abuse controls;
- timeout behavior;
- retry behavior;
- logging;
- secret handling;
- network segmentation;
- dependency/service availability;
- failure behavior when the AML service is unavailable.

The reference service is not a substitute for these production controls.

## 8. Browser and frontend boundaries

If using browser bridges, `<aml-gate>`, DOM annotations, or View Meaning™:

- confirm which data is trusted vs untrusted;
- test DOM mutation after evaluation;
- test script ordering/race conditions;
- test CSP/security-policy interaction;
- review extension/browser permissions;
- verify that client-side evidence is not treated as authoritative where server-side control is required;
- test degraded/offline behavior;
- ensure accessibility is preserved when content is suppressed or substituted.

## 9. AI/model-specific threats

For AI-generated interfaces, test:

- prompt-injection influence on declared purpose/policy inputs;
- model attempts to omit or falsify required semantic fields;
- contradictory purpose and content;
- tool/action escalation through generated UI;
- stale context or policy;
- adversarial personalization;
- generated content that bypasses intended AML evaluation;
- fallback paths that render without the intended gate.

Do not assume a model-generated declaration is truthful merely because it is machine-readable.

## 10. Failure-mode design

Decide explicitly what happens when:

- parsing fails;
- policy evaluation fails;
- verification fails;
- a receipt cannot be produced;
- a trust root cannot be resolved;
- a dependency is unavailable;
- AML and the production system disagree;
- latency exceeds budget;
- an unknown AML version appears.

Choose fail-open or fail-closed behavior deliberately per surface. Document why.

## 11. Privacy and data governance

Review:

- personal-data exposure in AML source, receipts, logs, and provenance;
- data minimization;
- retention;
- deletion requirements;
- consent state;
- jurisdictional requirements applicable to the deployment;
- whether evidence itself can become sensitive data.

A technically valid receipt can still contain data that should not be retained or disclosed.

## 12. Accessibility and human impact

Evaluate whether AML enforcement can:

- remove critical context;
- hide required controls;
- impair keyboard/navigation flows;
- create confusing fallback states;
- interfere with assistive technology;
- cause unsafe suppression in high-stakes workflows.

Accessibility checks must include the post-enforcement experience, not only the pre-enforcement markup.

## 13. Observability

Capture enough information to diagnose decisions without creating unnecessary sensitive logs.

Useful signals can include:

- policy/version;
- decision;
- receipt identifier;
- verification state;
- latency;
- error class;
- rollback state;
- disagreement markers;
- canary cohort.

## 14. Rollback and incident response

Before enforcement, test:

- immediate disable/rollback;
- policy rollback;
- version rollback;
- trust-root rollback/revocation;
- incident ownership;
- evidence preservation;
- communication path;
- criteria for returning to shadow mode.

## 15. Independent challenge

Before making a strong production claim, have someone outside the implementation path try to break or reproduce the evidence.

Useful starting points:

- [Public Challenge Map](../CHALLENGES.md)
- [Public Witness Protocol](../publications/AML_WITNESS_PROTOCOL.md)
- [Verify AML](../VERIFY.md)
- [Security Threat Model](../SECURITY_THREAT_MODEL.md)

## Decision record

A production-readiness review should end with one of:

- **NO-GO** — unresolved risk is unacceptable;
- **SHADOW ONLY** — useful for observation but not enforcement;
- **LIMITED CANARY** — bounded enforcement with rollback criteria;
- **PRODUCTION CANDIDATE** — security/operations review supports a scoped deployment;
- **PRODUCTION APPROVED BY THE DEPLOYING ORGANIZATION** — an organizational decision, not an ĀML certification claim.

Record the reasons, assumptions, unresolved risks, and owner.

## Claim boundary

This checklist is an engineering aid. Completing it does not create a certification, regulatory approval, security guarantee, standards-body endorsement, or official ĀRU authorization.

**The safest AML deployment is the one whose trust boundaries, failure modes, evidence, and rollback behavior are explicit before enforcement begins.**
