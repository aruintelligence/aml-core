# ĀML™ Public Challenge Map

## Do not merely read ĀML. Try to prove it wrong.

ĀML™ — ĀRU Meaning Language™ is easier to evaluate when criticism has a reproducible path.

This page collects the public challenge ladder: from a one-minute browser test to independent implementations that do not import the reference runtime.

The objective is not applause. The objective is evidence.

## Level 1 — One-minute decision test

Open:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

Observe the initial decision, change `restoration_value` from `1` to `5`, and inspect the resulting decision and receipt.

Reference rule:

```text
render_allowed = restoration_value >= attention_cost
```

Report unexpected behavior.

The prototype scores are declared/model inputs. They are not claimed objective scientific measurements of cognition, wellbeing, manipulation, or harm.

## Level 2 — Reproduce the proof locally

Use:

- [10-minute reproduction](docs/TRY_AML_10_MINUTES.md)
- [Verification guide](VERIFY.md)
- [Public Witness Protocol](publications/AML_WITNESS_PROTOCOL.md)

A useful report includes the exact commit/release, environment, input, expected result, actual result, and any receipt/hash/evidence identifier.

## Level 3 — Challenge a SHIPPED claim

Read:

- [Claims ledger](CLAIMS.md)
- [Machine-readable claims ledger](claims.json)
- [Proof map](publications/PROOF_MAP.md)

Pick one claim marked **SHIPPED** and attempt to reproduce the evidence path.

If the claim cannot be reproduced, file the failure. A failed reproduction is valuable evidence.

## Level 4 — Third-runtime witness challenge

GitHub issue:

https://github.com/aruintelligence/aml-core/issues/15

Goal: verify the published AML witness vector in another language/runtime without importing AML verifier internals.

Examples include Rust, Go, Java, Swift, C#, Ruby, PHP, Kotlin, Zig, C/C++, or another independently maintained implementation.

A PASS, FAIL, or MIXED result is useful when it includes reproducible evidence.

## Level 5 — Independent conformance implementation

GitHub issue:

https://github.com/aruintelligence/aml-core/issues/1

Goal: consume published conformance fixtures without importing the reference compiler internals and document all deviations from reference behavior.

This tests whether AML's public contracts can be implemented from the published surface rather than by copying implementation details.

## Level 6 — Independent semantic-release verifier

GitHub issue:

https://github.com/aruintelligence/aml-core/issues/56

Goal: verify AML semantic release proofs without importing or calling the JavaScript reference implementation.

The challenge includes canonical JSON behavior, Meaning Manifest verification, Ed25519 attestations, semantic lineage, semantic release proof verification, and deliberate tamper rejection.

## Level 7 — Try to break the interface-accountability thesis

AML's broader thesis is that AI-generated interfaces can carry explicit, inspectable meaning, policy, authority, provenance, and evidence around the decision to render.

Useful falsification attempts include:

- construct a case AML should ALLOW but suppresses
- construct a case AML should SUPPRESS but allows
- identify ambiguous canonicalization
- identify a receipt that verifies when it should fail
- identify a replay or authority boundary that can be bypassed
- identify an accessibility, consent, privacy, or policy decision that cannot be explained from the evidence
- identify semantic drift the release tooling fails to detect
- identify a SHIPPED claim not supported by its evidence path
- identify a specification requirement that cannot be implemented independently

Security-sensitive findings should follow [SECURITY.md](SECURITY.md) rather than being published prematurely.

## Public verification issue

General call for independent verification:

https://github.com/aruintelligence/aml-core/issues/88

The request is intentionally simple:

**Try it. Break it. Verify it. Publish what you find.**

## What counts as strong evidence

Strong evidence is reproducible and bounded. Include:

- exact AML commit or release
- exact input/artifact
- runtime and version
- reproduction command
- expected output
- actual output
- PASS / FAIL / MIXED
- receipt/hash/signature evidence where relevant
- mutation/tamper case where relevant
- specification ambiguity where relevant

## What a successful challenge does not prove

A successful technical reproduction does not by itself establish that AML is:

- a ratified global standard
- universally adopted
- scientifically validated for human cognition or wellbeing
- secure against every threat
- compliant with every law or regulation
- officially endorsed or certified by an outside organization

It establishes only what the evidence actually demonstrates.

## Start here by audience

- Developer: [AML for Developers](publications/AML_FOR_DEVELOPERS.md)
- AI/agent builder: [AML for AI Agents](publications/AML_FOR_AI_AGENTS.md)
- Enterprise evaluator: [AML for Enterprise](publications/AML_FOR_ENTERPRISE.md)
- Research/standards: [AML Standards and Research](publications/AML_STANDARDS_AND_RESEARCH.md)
- Skeptic: [Critic's Guide](publications/CRITICS_GUIDE.md)
- Security reviewer: [Security Threat Model](SECURITY_THREAT_MODEL.md)

## The standard AML should be held to

The project should become harder to dismiss because it becomes easier to test.

**Evidence over volume. Reproduction over reputation. Public disagreement over manufactured consensus.**
