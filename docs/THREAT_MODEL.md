# ĀML threat model

This document defines the project-maintained security boundaries used to guide review. It is not a claim of independent penetration testing or certification.

## Assets

High-value assets include governance decisions, policy state, signed transcripts, selective-disclosure commitments, trust roots, delegated authority, revocation state, package contents, release evidence, and the integrity of ALLOW/SUPPRESS outcomes presented to a renderer.

## Adversary goals

An attacker may try to:

- cause a SUPPRESS decision to render;
- mutate policy without the required authority;
- reuse a valid authorization for a different stream, epoch, prior state, or requested mutation;
- inflate a witness threshold with duplicate keys;
- use expired or revoked authority;
- forge or tamper with transcripts, disclosures, receipts, manifests, or signatures;
- exploit canonicalization ambiguity to obtain different hashes across runtimes;
- replay messages or authorizations outside their intended context;
- cause two runtimes to disagree while hiding the divergence;
- place credentials, private keys, or unintended files into a distributable package;
- exploit parser/server/browser surfaces to cross application trust boundaries.

## Trust assumptions

Cryptographic verification proves only the properties implemented by the verifier. Key possession is not equivalent to organizational identity, legal authority, ethical correctness, independent operation, or regulatory approval. Trust roots and policy inputs remain explicit verifier-controlled inputs.

Project-maintained Python and Go reference verifiers are useful conformance targets but are not counted as independent external implementations.

## Primary controls

Current controls include deterministic canonicalization, Ed25519 signatures, hash-chained transcripts, deterministic replay, replay guards, explicit scope/expiry/revocation checks, threshold distinct-key checks, delegated authority verification, selective-disclosure inclusion proofs, disagreement localization, package-content checks, API stability gates, cross-platform consumer tests, CodeQL analysis, and CI conformance suites.

## Residual risk

The project does not claim complete formal verification, immunity from implementation defects, secure production deployment defaults, complete side-channel resistance, independent key custody, universal policy correctness, or validated human-outcome measurement. Deployers remain responsible for authentication, authorization, TLS, rate limiting, isolation, logging, key management, dependency review, platform hardening, and application-specific threat modeling.
