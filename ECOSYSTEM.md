# ĀML™ Ecosystem Map

ĀML is growing beyond a compiler repository into an interoperable set of adoption, verification, policy, research, trust, enterprise, and protocol surfaces.

## Try it

- Browser playground: https://aruintelligence.github.io/aml-core/playground.html
- View Meaning™: https://aruintelligence.github.io/aml-core/view-meaning.html
- Official AML authorization verifier: https://aruintelligence.github.io/aml-core/official-verify.html
- Zero-install browser example: `examples/browser-drop-in.html`
- Out-of-the-box guide: `docs/OUT_OF_THE_BOX.md`

## Adopt it

- Plain JavaScript starter: `starters/plain-js/`
- React starter: `starters/react/`
- Next.js starter: `starters/nextjs/`
- React accountable UI adapter: `adapters/react.js`
- AI Interface Firewall™ guide: `docs/AI_INTERFACE_FIREWALL.md`
- Why teams would use AML: `docs/WHY_TEAMS_USE_AML.md`
- 30-minute enterprise pilot: `pilots/enterprise-30min/`
- HTTP reference service: `server/httpServer.js`
- OpenAPI contract: `protocol/aml-http.openapi.yaml`
- Copy-paste Meaning Gate workflow: `examples/github-actions/meaning-gate.yml`

## See the flagship story

- AI Interface Firewall before/after demo: `demos/interface-firewall/`
- semantic risk diff
- policy diff
- PR Meaning Gate™
- View Meaning receipt inspection
- proof-carrying output

## Federate it

AML includes an experimental cross-system interoperability layer:

- capability negotiation: `runtime/capabilityNegotiation.js`
- portable policy passports: `runtime/policyPassport.js`
- content-addressed artifact bundles: `runtime/contentAddressedBundle.js`
- selective disclosure commitments: `runtime/selectiveDisclosure.js`
- negotiated federated exchanges: `runtime/federatedExchange.js`
- causal execution DAGs: `runtime/causalExecutionGraph.js`
- versioned wire envelopes: `protocol/wireProtocol.js`
- replay resistance: `protocol/replayGuard.js`
- canonical JSON: `protocol/canonicalJson.js`
- golden test vectors: `protocol/test-vectors.json`
- machine-readable runtime discovery: `protocol/discovery.json`
- protocol identifier registry: `protocol/registry.json`
- interoperability guide: `docs/INTEROPERABILITY_STANDARD.md`

The design target is explicit compatibility negotiation and verifiable exchange between independently implemented AML runtimes rather than silent downgrade or shared-process trust.

## Build the trust fabric

- delegated trust chains: `runtime/trustDelegation.js`
- threshold authorization: `runtime/thresholdAuthorization.js`
- bounded capability tokens: `runtime/capabilityToken.js`
- append-only transparency logs: `runtime/transparencyLog.js`
- revocation registries: `runtime/revocationRegistry.js`
- Proof-Carrying Interface™ manifests: `runtime/proofCarryingInterface.js`
- consent continuity: `runtime/consentLedger.js`
- audit streams/checkpoints: `runtime/auditStream.js`, `runtime/auditAttestation.js`
- attention ledger/integrity: `runtime/attentionLedger.js`, `runtime/attentionIntegrity.js`
- execution provenance: `compiler/provenanceGraph.js`
- Merkle receipt batching: `runtime/receiptMerkle.js`

## Verify official AML identity

Open-source software rights and official project/brand authorization are separate.

- claimed-mark registry: `OFFICIAL_MARKS.json`
- public authorization index: `OFFICIAL_AUTHORIZATIONS.json`
- canonical ĀRU trust roots: `BRAND_TRUST_ROOTS.json`
- production public verification key: `keys/aru-aml-brand-prod-2026-09-08-01-public.pem`
- credential signing/verification: `runtime/brandAuthorization.js`
- canonical trust verification: `runtime/brandTrust.js`
- CLI verifier: `bin/aml-brand-verify.js`
- GitHub Action: `actions/verify-official/`
- browser verifier: `docs/official-verify.html`
- HTTP verification contract: `protocol/aml-http.openapi.yaml`
- key operations guidance: `docs/BRAND_KEY_OPERATIONS.md`

A self-signed credential can be cryptographically valid while still not being officially authorized by ĀRU. Official verification additionally requires an active, non-revoked signer fingerprint in the canonical trust-root registry.

Production private signing material is not stored in GitHub.

## Verify technical compatibility

- AML Conformance workflow: `.github/workflows/conformance.yml`
- Conformance checker: `scripts/check-conformance.js`
- Versioned fixture inventory: `conformance/manifest.json`
- compatibility levels: `conformance/levels.json`
- AML Compatible badge rules: `docs/CONFORMANCE_BADGE.md`
- independent replication protocol: `REPLICATION.md`

Technical conformance is intentionally separable from official branding, endorsement, partnership, or certification identity.

## Build against standards

- RFC process/index: `rfcs/README.md`
- RFC 0001 — Abstract Meaning Tree
- RFC 0002 — Render Decision Protocol
- RFC 0003 — Accountable Execution Receipt
- RFC 0004 — User-Owned Policy Profiles
- RFC 0005 — Cross-System Interoperability Layer
- RFC 0006 — Causal Execution Graphs
- RFC 0007 — AML Trust Fabric
- RFC 0008 — Compatibility Levels
- RFC 0009 — Bounded Capability Tokens + Replay Resistance
- RFC 0010 — Proof-Carrying Interfaces + Revocation
- RFC 0011 — Official Brand Authorization Credentials
- standardization path: `STANDARDIZATION.md`
- governance: `GOVERNANCE.md`

## Review security

- Security policy: `SECURITY.md`
- Threat model: `SECURITY_THREAT_MODEL.md`
- brand key custody: `docs/BRAND_KEY_OPERATIONS.md`
- adversarial testing issue template: `.github/ISSUE_TEMPLATE/adversarial-test.md`
- accessibility review template: `.github/ISSUE_TEMPLATE/accessibility-review.md`

## Inspect meaning in the browser

- View Meaning™ web inspector: `docs/view-meaning.html`
- browser-extension prototype: `extensions/view-meaning/`
- extension security/privacy tests: `test/view-meaning-extension.test.js`

The extension prototype uses a narrow user-invoked permission model and performs receipt/credential verification locally, fetching only the public trust-root registry when needed.

## Benchmark it

- Benchmark harness: `benchmarks/run.js`
- Benchmark fixture/reporting rules: `benchmarks/FIXTURES.md`
- Conformance fixtures: `conformance/manifest.json`

## Extend it

- Integration request template: `.github/ISSUE_TEMPLATE/integration-request.md`
- View Meaning browser-extension spec: `docs/VIEW_MEANING_BROWSER_EXTENSION.md`
- v1.4 adoption roadmap: `docs/V1_4_ADOPTION_ROADMAP.md`
- current roadmap: `ROADMAP.md`
- full JavaScript API: `API.md`

## Open contribution targets

The repository maintains concrete public issues for:

- independent conformance implementations
- second-runtime wire interoperability
- adversarial integrity/accountability review
- independent security review
- real framework integrations
- package distribution

The goal is outside scrutiny and reproducibility, not manufactured social proof.

## Release status

- stable release: `v1.3.0`
- public architecture prerelease: `v1.4.0-rc.1`
- prerelease notes: `RELEASE_NOTES_1.4.0_RC1.md`

The package/CLI/capability version remains v1.3.0 until the stable v1.4 package-release path is completed.

## Positioning

> **AI proposes. ĀML evaluates. Systems negotiate. The interface renders. The receipt explains.**

ĀML is a working research prototype. Its software accountability, integrity, interoperability, and protocol properties can be tested directly. Claims about human attention, wellbeing, ethics, identity, authorization, or accessibility outcomes require evidence or systems beyond the AML software itself.
