# ĀML Security Hardening Bulletin — September 8, 2026

**Status: SHIPPED public evidence bulletin**

**Author:** Daniel Jacob Read IV  
**Steward:** ĀRU Intelligence Inc.™

ĀML is being developed in public as a working research prototype for meaning-native, policy-aware, accountable interfaces. This bulletin documents a concentrated hardening pass across release safety, receipts, signatures, quorum logic, trust delegation, canonicalization, proof structures, content-addressed bundles, causal graphs, wire/version negotiation, and transparency logs.

The purpose of this publication is not to claim perfection. It is to make the defects, corrections, and evidence visible enough for independent review.

## What changed

### Release publication safety

A write-capable GitHub release workflow could previously be triggered in ways that made stale release identity dangerous. The workflow was made manual-only, main-only, contract-driven, and preflight-checked. Repository guardrails now reject automatically triggered write-capable workflows.

### Receipt JSON portability

Default accountable receipts could carry JavaScript `Infinity` inside attention state. JSON has no `Infinity`, so ordinary serialization could convert it to `null` and change receipt material. The receipt pipeline now uses a JSON-safe representation for an unbounded budget while preserving direct in-memory compatibility where needed.

### Receipt inner-binding verification

Receipt verification previously focused too heavily on the outer receipt hash. The verifier now independently checks that embedded intent, AML source, simulations, decisions, rendered output, summary counts, audit state, and attention state agree with their committed hashes and structure.

### Signed attribution

Several older signature surfaces authenticated payloads without authenticating all displayed attribution metadata. New attestations bind signer/time metadata to the signed material. Legacy signatures remain verifiable only for what they actually authenticated; legacy free-floating attribution is not retroactively described as trusted identity.

### Public-key fingerprint normalization

New cryptographic attestations use SHA-256 over raw DER public-key bytes for fingerprints. Legacy verification preserves historical behavior only where needed for backward compatibility.

### Audit checkpoints and build attestations

Audit checkpoint signer identity and build-attestation signer/time/path metadata are now covered by versioned authenticated material. Current build attestations bind metadata and manifest bytes rather than relying only on a separately asserted manifest hash.

### Threshold authorization

The authorization threshold is now part of the signed material. An attacker can no longer rewrite a valid 2-of-3 authorization into 1-of-3 without invalidating it. Legacy unversioned threshold artifacts cannot satisfy current authority mode because their quorum was never authenticated.

### Verification quorum semantics

Only distinct keys that sign a valid verdict count toward a positive verification quorum. A correctly signed dissenting or invalid report no longer helps create consensus.

### Trust delegation

Hash-only legacy delegation objects are now explicitly integrity-only. Cryptographic delegation requires a pinned root key fingerprint and hop-by-hop key continuity so a party cannot self-sign an object that merely claims a trusted issuer name.

### Credential lifetime validation

Capability credentials and brand authorizations reject malformed or inverted issuance/expiration windows. Verifiers fail closed on invalid time fields and invalid verifier-supplied evaluation times.

### Canonical JSON collision hardening

Canonical JSON now rejects values outside JSON's data model instead of silently collapsing distinct JavaScript values into identical authenticated bytes. This includes non-finite numbers, `undefined`, functions, symbols, bigints, and non-plain objects.

### Wire lifetime validation

Wire lifetime parsing was hardened so malformed timestamps cannot silently behave as immortal values. The lower-level replay primitive intentionally remains distinct from the full wire-protocol validator; an attempted change that crossed that architectural boundary was closed unmerged after CI exposed the incompatibility.

### Protocol-version negotiation

Capability negotiation and wire-session negotiation now compare dotted numeric versions segment-by-segment rather than lexicographically. `1.10` correctly orders after `1.9`, and `1.2.10` after `1.2.9`.

### Selective-disclosure verification

Malformed disclosure proof containers and entries now fail closed rather than throwing. Duplicate claim keys are rejected as ambiguous. Existing v1 commitment byte semantics were preserved rather than silently redefined.

### Merkle inclusion proofs

Receipt inclusion verification now binds the claimed leaf index to the left/right Merkle proof path. Rewriting index metadata can no longer leave a proof verified. Malformed proof hashes, path positions, versions, and structures fail closed.

### Content-addressed bundle completeness

Bundle verification now requires exact agreement between the index key set and the file key set. A phantom index-only artifact cannot be added, re-rooted, and accepted while the corresponding file is absent.

### Causal graph topology

Causal graph verification now checks that each map key equals the embedded event hash and independently recomputes roots and heads. Rewritten topology metadata cannot survive verification merely because individual event hashes are valid.

### Transparency-log fail-open closure

A malformed transparency log whose `entries` field was an object could previously skip iteration and appear valid as an empty log. Verification now requires an array, validates hash fields and entry structure, and fails closed on hostile input.

## Evidence trail

Key merged pull requests in this hardening sequence include:

- PR #23 — release workflow safety
- PR #24 — receipt JSON portability
- PR #25 — receipt inner-binding verification
- PR #26 — signed receipt/policy-pack attribution and fingerprint correction
- PR #27 — audit checkpoint and build-attestation attribution
- PR #28 — threshold authorization quorum binding
- PR #29 — dissent cannot satisfy positive verification quorum
- PR #30 — cryptographic trust-delegation continuity
- PR #31 — credential lifetime fail-closed validation
- PR #32 — strict canonical JSON authenticated-byte contract
- PR #39 — numeric protocol version negotiation
- PR #40 — selective-disclosure verifier fail-closed behavior
- PR #41 — Merkle index/path binding
- PR #42 — content bundle index/file exact-set agreement
- PR #43 — causal graph topology binding
- PR #44 — transparency-log fail-open closure

The repository also contains deliberately closed experiments where CI or architecture review showed that a proposed change crossed a contract boundary. Those branches were not merged simply to increase activity.

## Verification discipline

Material changes are expected to pass the repository's engineering gate and automated checks, including:

- CI
- ĀML Conformance
- ĀML Project Contract
- ĀML Release Coherence

The repository also exercises deterministic receipt replay, ALLOW/SUPPRESS fixtures, public claim guards, verifier interoperability, immutable verifier-contract snapshots, Python witness vectors, black-box Python and Go verification, CLI compilation, bundle integrity, semantic linting, inspect/explain output, and benchmarks.

## What this does not claim

This hardening pass does **not** establish that ĀML is a ratified global standard, broadly deployed in production, independently security-audited, or objectively capable of measuring human cognition or wellbeing. It does not make an AI's declared intent truthful, does not replace WCAG conformance or assistive-technology testing, and does not make a cryptographically valid artifact morally, legally, or institutionally correct.

What it does establish is narrower and testable: specific public defects were identified, reproduced, corrected, regression-tested, and merged through the project's quality gates.

## Invitation to challenge it

Do not trust this bulletin because it is confident. Check the code, run the tests, reproduce the failure modes, and file the disagreements.

Repository: https://github.com/aruintelligence/aml-core  
Live reference: https://aruintelligence.github.io/aml-core/  
Claims ledger: ../CLAIMS.md  
Verification guide: ../VERIFY.md

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**.
