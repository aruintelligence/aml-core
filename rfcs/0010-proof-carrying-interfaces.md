# RFC 0010 — Proof-Carrying Interfaces and Revocation

Status: Draft

## Abstract

This RFC defines a compact manifest that binds rendered interface output to the accountability artifacts that justify it, plus a tamper-evident mechanism for revoking previously trusted artifacts.

## Proof-carrying interface manifest

An `aml-proof-carrying-interface/1` manifest binds the rendered output SHA-256 hash and optional hashes for:

- execution receipt
- policy passport
- conformance claim
- provenance graph
- causal execution graph

The manifest itself is hash-bound.

A verifier MUST reject the manifest when the supplied output or any supplied bound artifact does not match its committed hash.

The manifest proves artifact binding, not correctness of the underlying policy, intent, accessibility claim, or rendered content.

## Why carry proof with the interface?

In a distributed AI system, the runtime that renders an interface may not be the runtime that proposed it, evaluated policy, or issued the user policy passport. A proof-carrying interface lets a receiving system independently determine which accountability artifacts belong to the exact output it received.

Potential uses include:

- browser or agent inspection tools;
- cross-service interface delivery;
- regulated workflow archives;
- signed UI release artifacts;
- View Meaning-compatible inspection;
- offline verification of an interface snapshot.

## Revocation

AML defines an `aml-revocation-registry/1` as an append-only hash chain over revoked artifact hashes.

A revocation entry binds:

- sequential index
- previous registry head
- revoked artifact hash
- optional reason
- optional revocation timestamp
- entry hash

Implementations MUST verify the registry chain before trusting a revocation lookup result.

Revocation may apply to artifacts such as:

- capability tokens
- delegated-authority objects
- policy passports
- policy packs
- conformance claims
- signing keys represented by fingerprint artifacts

## Security considerations

A local hash-chain registry is not automatically globally authoritative. Distributed systems must define which revocation registries they trust, how registry heads are distributed, and how stale/offline state is handled.

Proof-carrying interfaces do not replace normal application security, content sanitization, browser security, accessibility testing, or legal/regulatory controls.
