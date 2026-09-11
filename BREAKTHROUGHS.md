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

The adapter accepts generated components plus explicit governance metadata, evaluates each component through the existing streaming/deployment firewall, and returns components permitted to render separately from components suppressed before rendering.

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

ĀML now includes a project-defined multi-party governance witness quorum.

Signed, replay-valid governance transcripts can be evaluated under a threshold policy requiring enough **distinct eligible signing keys** to attest to the same transcript root.

The policy can independently specify:

- a minimum witness threshold;
- trusted key fingerprints;
- revoked key fingerprints;
- required signer scope;
- unique-key enforcement.

Witnesses are grouped by transcript root. Duplicate signing keys do not inflate a quorum. Revoked keys are excluded. Signatures from keys outside the verifier's explicit trust set do not become trusted merely because their public keys are embedded in the artifact.

Project surfaces:

- `evaluateGovernanceWitnessQuorum(...)`;
- `verifyGovernanceWitnessQuorum(...)`;
- `aml-governance-witness-quorum`;
- `schemas/governance-witness-quorum.schema.json`;
- `docs/MULTIPARTY_GOVERNANCE_WITNESS.md`;
- `publications/MULTIPARTY_GOVERNANCE_WITNESS.md`.

Protocol:

```text
aml-governance-witness-quorum/1
```

This creates a threshold-attestation primitive for governed AI interface evidence. It is **not** Byzantine consensus, identity proofing, a timestamp authority, independent external validation, standards-body recognition, or evidence that outside organizations currently operate witness nodes.

## The frontier

The next technical frontiers are:

1. independently reproduced Agent UI, continuous-stream, transcript, signature, and witness-quorum verification;
2. external adapters for distinct generative-UI protocols;
3. a second independently maintained runtime implementing the public contracts;
4. cross-runtime transcript replay with precise disagreement localization;
5. signer authorization rotation and revocation with externally maintained witness trust roots;
6. bounded real-application pilots comparing shadow and enforce modes;
7. adversarial tests for false ALLOW decisions, truncated streams, rehashed false transcripts, signature substitution, trust-root confusion, witness duplication, and quorum splitting;
8. policy changes and capability negotiation during live sessions without weakening auditability;
9. privacy-preserving witness proofs that reveal enough to verify a decision without necessarily disclosing the entire governed interface.

The goal is not to make ĀML impossible to criticize. The goal is to make its claims increasingly precise, executable, portable, and falsifiable.
