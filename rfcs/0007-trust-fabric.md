# RFC 0007 — AML Trust Fabric

Status: Draft

## Abstract

This RFC defines a minimal trust fabric for AML interoperability: canonical JSON serialization, delegated authority, threshold authorization, and append-only transparency logs.

## Goals

An AML ecosystem should not assume that one runtime, one organization, or one key controls every important decision. Trust artifacts must therefore be independently inspectable, content-stable, and capable of expressing bounded authority.

## Canonical serialization

Objects that are hashed or signed MUST be serialized with stable recursive key ordering. The reference implementation exposes `canonicalJSONStringify`.

This is not a claim of compatibility with any external canonical-JSON standard. Independent implementations MUST reproduce AML canonicalization test vectors exactly before claiming signature interoperability.

## Delegated authority

A delegation binds:

- issuer
- delegate
- delegated capabilities
- optional issue/expiry times
- a hash of the canonical delegation body

Delegation chains MUST preserve issuer → delegate continuity. Implementations MUST reject broken, expired, mutated, or capability-insufficient chains.

The current reference delegation primitive is hash-bound but not itself signed. Production trust systems should bind delegations to authenticated signer identities.

## Threshold authorization

Sensitive actions MAY require M-of-N independent Ed25519 signatures over one canonical payload.

Duplicate public-key fingerprints MUST NOT count twice toward a threshold.

Typical uses include:

- publishing a high-impact policy pack
- changing protocol registries
- approving an institutional policy profile
- rotating trust roots

Threshold signatures prove that enough configured keys signed the exact payload. They do not prove the signers were trustworthy or competent.

## Transparency log

The AML transparency log is an append-only SHA-256 hash chain over committed payload hashes.

Each entry binds:

- sequential index
- previous entry hash
- payload hash
- optional timestamp
- entry hash

Mutation, deletion from the middle, reordering, or head substitution MUST invalidate verification.

## Security boundary

Hash chains and signatures provide integrity properties. They do not make underlying declarations true, ethical, legal, or safe.
