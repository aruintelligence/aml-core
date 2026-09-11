# ĀML technical breakthroughs

This page publishes the project's strongest **shipped technical milestones** and the evidence that supports them.

It deliberately does **not** use “breakthrough” to mean external scientific validation, standards-body recognition, broad adoption, certification, or independent endorsement. Those are separate claims and require separate evidence.

## 1. A render decision can be made before pixels

ĀML can evaluate declared interface intent before a renderer receives the component.

Core prototype rule:

```text
render_allowed = restoration_value >= attention_cost
```

Live falsifiable proof:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

One-command local reproduction:

```bash
npm run proof
```

Publishable machine report:

```bash
npm run proof:report
```

## 2. Meaning and policy can remain separate from the renderer

The project ships browser bridges, a React adapter, a streaming interface firewall, deployment/shadow-mode wrappers, and a renderer-agnostic agent-UI governance adapter.

## 3. Generated-interface decisions can carry evidence

ĀML execution paths can emit deterministic receipts and hashes that can be inspected after the decision. Project-controlled reports remain project evidence until an outside party independently runs and publishes them.

## 4. Meaning can become a release-control primitive

The repository includes Meaning Fingerprints, Meaning Manifests, signed manifests, append-only Meaning Lineage, Semantic Release Proofs, release-key trust policy, threshold/quorum authorization, in-toto statement export, and GitHub attestation verification tooling.

## 5. Interface accountability can extend across systems

The runtime includes capability negotiation, policy passports, replay protection, content-addressed bundles, selective disclosure, trust delegation, transparency logs, revocation registries, causal execution graphs, and Proof-Carrying Interface™ artifacts.

## 6. Verification is designed to permit disagreement

ĀML's public verification path explicitly accepts **PASS / FAIL / MIXED** results. Internal CI, project-maintained reference runtimes, clone counts, or outreach activity are not external evidence.

## 7. The governance boundary can cross process and language boundaries

The Agent UI governance contract is exposed through JavaScript API, CLI, and HTTP, with machine-readable schemas and conformance vectors. External runtimes can hand a JSON envelope to a separate governance process without importing ĀML internals.

## 8. Governance can remain present while an interface is still being generated

The continuous governance stream evaluates incremental semantic nodes and can return ALLOW/SUPPRESS decisions before later nodes exist. The reference transport uses HTTP/NDJSON.

## 9. A live governance session can become replayable evidence

Governance-stream transcripts are SHA-256 hash chained and then deterministically replayed. Replay verification is designed to reject a stronger attack where someone falsifies an output and recomputes an otherwise valid new hash chain.

## 10. Transcript integrity, signature validity, and trust can remain separate

Replayable transcripts can be signed with Ed25519. Verification separately reports transcript validity, replay validity, signature validity, and whether the key fingerprint belongs to an explicitly supplied trust set. An embedded public key is not a trust root.

## 11. Multiple trusted keys can witness the same governed interface decision

ĀML includes a project-defined multi-party governance witness quorum. Signed, replay-valid governance transcripts can be evaluated under a threshold policy requiring enough distinct eligible signing keys to attest to the same transcript root.

Protocol:

```text
aml-governance-witness-quorum/1
```

This is a threshold-attestation primitive, not Byzantine consensus, identity proofing, a timestamp authority, independent external validation, standards-body recognition, or evidence that outside organizations currently operate witness nodes.

## 12. Cross-runtime disagreement can be localized instead of hidden

Two governance transcripts can be compared entry by entry. When executions diverge, `aml-runtime-disagreement-report/1` identifies the first observable disagreement and hashes both sides of that boundary.

The localizer does not declare the project runtime correct. Correctness still requires an external contract, conformance vector, witness policy, or adjudication rule.

## 13. Governance evidence can be selectively disclosed

ĀML now includes a project-defined selective-disclosure format for governance transcripts.

A Merkle commitment is built over all transcript entry hashes. Selected entries can then be revealed with inclusion proofs while undisclosed message bodies remain absent from the disclosure artifact.

Project surfaces:

- `createGovernanceDisclosure(...)`;
- `verifyGovernanceDisclosure(...)`;
- `aml-governance-disclose`;
- `aml-governance-disclosure-verify`;
- `schemas/governance-selective-disclosure.schema.json`;
- `docs/SELECTIVE_GOVERNANCE_DISCLOSURE.md`;
- `publications/SELECTIVE_GOVERNANCE_DISCLOSURE.md`.

Protocol:

```text
aml-governance-selective-disclosure/1
```

Verification checks disclosed-entry hashes and their Merkle inclusion paths. It can also require externally supplied expected transcript and Merkle roots so a verifier does not have to trust roots embedded in the disclosure artifact itself.

This is **selective disclosure, not zero-knowledge proof**. It still reveals metadata including the source entry count, selected indices, disclosed entries, transcript root, and Merkle commitment. A valid Merkle proof demonstrates membership in a commitment; authenticity still requires the commitment or transcript root to come from a trusted signed, witnessed, published, or otherwise authenticated source.

The architectural point is that future AI-interface accountability does not have to require publishing every governed detail to prove a smaller fact about the session.

## The frontier

The next technical frontiers are:

1. independent reproduction of Agent UI, streaming, transcript, signature, witness-quorum, disagreement-localization, and disclosure contracts;
2. external adapters for distinct generative-UI protocols;
3. a genuinely independently maintained runtime implementing the public contracts;
4. signed or witnessed disclosure commitments with explicit revocation and signer scope;
5. stronger privacy proofs, including research toward zero-knowledge statements about governed decisions without revealing message bodies;
6. machine-readable adjudication policies for known cross-runtime disagreements;
7. live policy and capability changes during a governance stream without destroying replayability;
8. bounded real-application pilots comparing shadow and enforce modes;
9. adversarial tests for false ALLOW decisions, truncated streams, rehashed false transcripts, signature substitution, trust-root confusion, witness duplication, quorum splitting, cross-runtime divergence, and disclosure-root substitution.

The goal is not to make ĀML impossible to criticize. The goal is to make its claims increasingly precise, executable, portable, privacy-aware, and falsifiable.
