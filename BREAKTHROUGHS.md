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

A Merkle commitment can be built over transcript entry hashes and selected entries can be revealed with inclusion proofs while undisclosed message bodies remain absent.

Protocol:

```text
aml-governance-selective-disclosure/1
```

This is selective disclosure, not zero-knowledge proof. Authenticity still requires a trusted signed, witnessed, published, or otherwise authenticated commitment or transcript root.

## 14. Policy can change during generation without disappearing from history

ĀML continuous-governance sessions can make default policy changes explicit while an interface is still streaming.

A live transition enters the stream as `aml-governance-stream-policy-update/1` and is acknowledged as `aml-governance-stream-policy-applied/1`. Each accepted update advances a monotonically increasing policy epoch and records hashes of the previous policy state, new policy state, and active context.

Because transitions are part of the same transcript as interface nodes and decisions, policy mutation remains deterministically replayable. This records and applies policy changes; it does not itself authorize them.

## 15. A partial disclosure can be anchored by a signed commitment

ĀML can sign the compact commitment behind a selective governance disclosure with Ed25519. The signed material contains the source transcript root, source entry count, and Merkle root committing to every transcript entry hash.

Protocols:

```text
aml-governance-disclosure-commitment/1
aml-signed-governance-disclosure-commitment/1
```

The verifier separates signature validity, verifier-controlled key trust, revocation policy, signer scope, and whether the disclosure matches the signed commitment. A valid signature still does not establish real-world identity, independent witnessing, certification, external adoption, or official ĀRU authorization.

## 16. A live policy transition can require threshold cryptographic authority

ĀML can now optionally protect live governance-policy changes with a threshold of trusted Ed25519 signatures before policy state is allowed to mutate.

The transition that gets signed is bound to four things:

- the exact governance-stream transmission;
- the expected current policy epoch;
- the SHA-256 of the exact previous policy state;
- the exact requested update fields.

Protocols:

```text
aml-governance-policy-transition/1
aml-governance-policy-transition-authorization/1
```

A protected stream can specify a verifier-controlled policy containing a signature threshold, trusted key fingerprints, revoked fingerprints, required signer scope, and trusted-key requirements. Duplicate signing keys cannot satisfy a distinct-key threshold.

If authorization is missing, the eligible-signature threshold is not met, or the signed transition is bound to a different epoch, prior state, transmission, or requested change, the policy update is rejected **before state mutation**.

Project surfaces:

- `createGovernancePolicyTransition(...)`;
- `signGovernancePolicyTransition(...)`;
- `createGovernancePolicyTransitionAuthorization(...)`;
- `verifyGovernancePolicyTransitionAuthorization(...)`;
- `transitionMatchesUpdate(...)`;
- `schemas/governance-policy-transition-authorization.schema.json`;
- `docs/AUTHORIZED_LIVE_POLICY_TRANSITIONS.md`;
- `publications/AUTHORIZED_LIVE_POLICY_TRANSITIONS.md`.

This advances live governance from replayable mutation toward cryptographically constrained mutation. It is still not universal identity proofing, organizational approval, regulatory authorization, external validation, or official ĀRU authorization. The verifier's trusted-key configuration remains an explicit authority decision.

## The frontier

The next technical frontiers are:

1. independent reproduction of the growing governance contract stack;
2. external adapters for distinct generative-UI protocols;
3. a genuinely independently maintained runtime implementing the public contracts;
4. policy-transition authorization delegated through explicit trust chains instead of static key lists;
5. multi-party witness quorums over selective-disclosure commitments;
6. stronger privacy proofs, including research toward zero-knowledge statements about governed decisions without revealing message bodies;
7. machine-readable adjudication policies for cross-runtime disagreement;
8. bounded real-application pilots comparing shadow and enforce modes;
9. adversarial testing for false ALLOW decisions, unauthorized policy transitions, replay across epochs, revoked-key reuse, threshold bypass, transcript substitution, disclosure substitution, and cross-runtime divergence.

The goal is not to make ĀML impossible to criticize. The goal is to make its claims increasingly precise, executable, portable, privacy-aware, and falsifiable.
