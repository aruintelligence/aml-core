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

The adapter accepts generated components plus explicit governance metadata, evaluates each component through the existing streaming/deployment firewall, and returns two outputs:

- components permitted to render;
- components suppressed before rendering.

Example:

```bash
node examples/agent-ui-governance.mjs
```

Contract identifiers:

- `aml-agent-ui-envelope/1`
- `aml-agent-ui-governance-result/1`

This project-defined adapter is intentionally protocol-neutral. It does **not** claim native compatibility with MCP Apps, A2UI, OpenUI, or another external generative-UI protocol. Its purpose is to prove the governance boundary can be expressed independently of a specific renderer.

## 3. Generated-interface decisions can carry evidence

ĀML execution paths can emit deterministic receipts and hashes that can be inspected after the decision.

The one-command proof report records the execution environment and deterministic replay hashes in `aml-proof-report.json`, allowing a tester to archive or publish the exact observed result instead of paraphrasing it.

Project-controlled reports remain project evidence. They become independent evidence only when an outside party runs and publishes them independently.

## 4. Meaning can become a release-control primitive

The repository includes Meaning Fingerprints, Meaning Manifests, signed manifests, append-only Meaning Lineage, Semantic Release Proofs, release-key trust policy, threshold/quorum authorization, in-toto statement export, and GitHub attestation verification tooling.

The practical thesis is that a software release can be checked not only for changed bytes, but also for declared semantic change and the authority under which that change is released.

These are project-defined prototype contracts, not externally ratified supply-chain standards.

## 5. Interface accountability can extend across systems

The runtime includes capability negotiation, policy passports, replay protection, content-addressed bundles, selective disclosure, trust delegation, transparency logs, revocation registries, causal execution graphs, and Proof-Carrying Interface™ artifacts.

The architectural direction is broader than one webpage: meaning, policy, authority, and evidence can travel with an interface decision across system boundaries.

## 6. Verification is designed to permit disagreement

ĀML's public verification path explicitly accepts **PASS / FAIL / MIXED** results.

Canonical independent-verification issue:

https://github.com/aruintelligence/aml-core/issues/88

Evidence ladder:

- E0 — concept / proposal
- E1 — project-authored demonstration
- E2 — automated repository verification
- E3 — independent reproduction
- E4 — independent implementation
- E5 — external pilot evidence
- E6 — production deployment evidence
- E7 — multi-party ecosystem evidence

The project must not promote internal CI, project-maintained reference runtimes, clone counts, or outreach activity into external evidence.

## 7. The governance boundary can cross process and language boundaries

The Agent UI governance contract is now exposed through three equivalent project surfaces:

- JavaScript API: `evaluateAgentUI(...)`;
- CLI: `aml-agent-ui`;
- HTTP: `POST /v1/agent-ui/evaluate` via `aml-agent-ui-serve`.

Machine-readable input/output schemas and a mixed ALLOW/SUPPRESS golden vector are included in the repository.

That changes the integration boundary materially: an external renderer or agent runtime no longer needs to import ĀML internals to ask whether generated components are renderable. It can hand a JSON envelope to a separate governance process and receive the governed component sets and decision evidence back.

Documentation:

- `docs/AGENT_UI_GATEWAY.md`
- `schemas/agent-ui-envelope.schema.json`
- `schemas/agent-ui-result.schema.json`
- `conformance/agent-ui/mixed.json`

This is a shipped project technical milestone, not evidence that another language, vendor, runtime, or protocol has independently implemented the contract.

## 8. Governance can remain present while an interface is still being generated

The continuous governance stream extends the cross-process boundary from complete envelopes to incremental semantic nodes.

A session is opened once, nodes are evaluated as they arrive, and each node can receive a decision before later nodes exist. The stream is finalized explicitly and produces a session summary.

Project surfaces:

- `aml-governance-stream` CLI;
- `aml-governance-stream-serve` HTTP gateway;
- `POST /v1/governance/stream` using NDJSON;
- `createGovernanceStreamSession(...)` programmatic API;
- `schemas/governance-stream-message.schema.json`;
- `conformance/governance-stream/mixed.ndjson`.

Core stream contracts:

- `aml-governance-stream-open/1`
- `aml-governance-stream-node/1`
- `aml-governance-stream-decision/1`
- `aml-governance-stream-finalize/1`
- `aml-governance-stream-result/1`

This matters for agentic and generative interfaces that stream, progressively reveal, or mutate UI over time. Governance no longer has to wait for a completed interface artifact.

The current reference transport is HTTP/NDJSON. It does not claim distributed consensus, exactly-once delivery, native compatibility with another UI protocol, or production network-security guarantees.

## 9. A live governance session can become replayable evidence

ĀML governance-stream transcripts convert a completed continuous-governance session into a portable artifact that records the exact input/output sequence.

Each entry is canonicalized and chained to the previous entry with SHA-256. Verification then performs two distinct checks:

1. **Hash-chain integrity** — detects ordinary mutation, deletion, insertion, or reordering.
2. **Deterministic replay** — re-executes the recorded inputs and requires the runtime to reproduce the recorded outputs.

The second check matters because someone could falsify an output and recompute a perfectly valid new hash chain. Replay verification is designed to reject that case when the changed output does not follow from the recorded inputs.

Project surfaces:

- `aml-governance-transcript`;
- `aml-governance-transcript-verify`;
- `createGovernanceStreamTranscript(...)`;
- `verifyGovernanceStreamTranscript(...)`;
- `schemas/governance-transcript.schema.json`;
- `docs/REPLAYABLE_GOVERNANCE_TRANSCRIPTS.md`.

Transcript protocol:

```text
aml-governance-stream-transcript/1
```

This makes a live interface-governance session easier to archive, challenge, reproduce, and compare across runtimes.

A critical limit remains explicit: a hash chain is not a signature. An unsigned transcript does not prove who created it or turn project-controlled evidence into independent evidence.

## The frontier

The next technical frontiers are:

1. independently reproduced Agent UI, continuous-stream, and transcript verification;
2. external adapters for distinct generative-UI protocols;
3. a second independently maintained runtime implementing the public contracts;
4. cross-runtime transcript replay and disagreement localization;
5. signed transcript authenticity with explicit trust roots, revocation, and signer scope;
6. bounded real-application pilots comparing shadow and enforce modes;
7. adversarial attempts to produce false ALLOW decisions, ambiguous receipts, stream truncation errors, rehashed false transcripts, or replay divergence;
8. policy changes and capability negotiation during live sessions without weakening auditability.

The goal is not to make ĀML impossible to criticize. The goal is to make its claims increasingly precise, executable, portable, and falsifiable.
