# ĀML Ecosystem Map

ĀML is growing beyond a compiler repository into a set of interoperable adoption, verification, policy, research, and cross-system protocol surfaces.

## Try it

- Browser playground: https://aruintelligence.github.io/aml-core/playground.html
- View Meaning™: https://aruintelligence.github.io/aml-core/view-meaning.html
- Zero-install browser example: `examples/browser-drop-in.html`
- Out-of-the-box guide: `docs/OUT_OF_THE_BOX.md`

## Adopt it

- Plain JavaScript starter: `starters/plain-js/`
- React starter: `starters/react/`
- Next.js starter: `starters/nextjs/`
- AI Interface Firewall guide: `docs/AI_INTERFACE_FIREWALL.md`
- Why teams would use AML: `docs/WHY_TEAMS_USE_AML.md`
- Copy-paste Meaning Gate workflow: `examples/github-actions/meaning-gate.yml`

## See the flagship story

- AI Interface Firewall before/after demo: `demos/interface-firewall/`
- Semantic risk diff
- Policy diff
- PR Meaning Gate
- View Meaning receipt inspection

## Federate it

AML now includes an experimental cross-system interoperability layer:

- capability negotiation: `runtime/capabilityNegotiation.js`
- portable policy passports: `runtime/policyPassport.js`
- content-addressed artifact bundles: `runtime/contentAddressedBundle.js`
- selective disclosure commitments: `runtime/selectiveDisclosure.js`
- negotiated federated exchanges: `runtime/federatedExchange.js`
- causal execution DAGs: `runtime/causalExecutionGraph.js`
- versioned wire envelopes: `protocol/wireProtocol.js`
- machine-readable runtime discovery: `protocol/discovery.json`
- interoperability guide: `docs/INTEROPERABILITY_STANDARD.md`

The design target is explicit compatibility negotiation and verifiable exchange between independently implemented AML runtimes rather than silent downgrade or shared-process trust.

## Verify it

- AML Conformance workflow: `.github/workflows/conformance.yml`
- Conformance checker: `scripts/check-conformance.js`
- Versioned fixture inventory: `conformance/manifest.json`
- AML Compatible badge rules: `docs/CONFORMANCE_BADGE.md`
- Independent replication protocol: `REPLICATION.md`

## Build against standards

- RFC process/index: `rfcs/README.md`
- RFC 0001 — Abstract Meaning Tree
- RFC 0002 — Render Decision Protocol
- RFC 0003 — Accountable Execution Receipt
- RFC 0004 — User-Owned Policy Profiles (Draft)
- RFC 0005 — Cross-System Interoperability Layer (Draft)
- RFC 0006 — Causal Execution Graphs (Draft)
- Policy Passport schema: `schema/policy-passport.schema.json`
- Wire Envelope schema: `schema/wire-envelope.schema.json`

## Review security

- Threat model: `SECURITY_THREAT_MODEL.md`
- Security policy: `SECURITY.md`
- Adversarial testing issue template: `.github/ISSUE_TEMPLATE/adversarial-test.md`
- Accessibility review template: `.github/ISSUE_TEMPLATE/accessibility-review.md`

## Benchmark it

- Benchmark harness: `benchmarks/run.js`
- Benchmark fixture/reporting rules: `benchmarks/FIXTURES.md`
- Conformance fixtures: `conformance/manifest.json`

## Extend it

- Integration request template: `.github/ISSUE_TEMPLATE/integration-request.md`
- View Meaning browser-extension spec: `docs/VIEW_MEANING_BROWSER_EXTENSION.md`
- v1.4 adoption roadmap: `docs/V1_4_ADOPTION_ROADMAP.md`

## Open contribution targets

The repository maintains concrete public issues for:

- independent conformance implementations;
- adversarial integrity/accountability review;
- real framework integrations.

The goal is outside scrutiny and reproducibility, not manufactured social proof.

## Positioning

> **AI proposes. ĀML evaluates. Systems negotiate. The interface renders. The receipt explains.**

ĀML is a working research prototype. Its software accountability, integrity, interoperability, and protocol properties can be tested directly. Claims about human attention, wellbeing, ethics, identity, authorization, or accessibility outcomes require evidence or systems beyond the AML software itself.
