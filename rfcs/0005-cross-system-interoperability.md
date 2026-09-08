# RFC 0005 — Cross-System Interoperability Layer

Status: Draft

## Summary

ĀML should be implementable across independent runtimes without requiring a shared codebase. This RFC defines the first interoperability layer around five primitives:

1. capability negotiation;
2. portable policy passports;
3. content-addressed bundles;
4. selective disclosure proofs;
5. a versioned wire envelope.

## Capability negotiation

Two AML-aware systems advertise supported protocol versions and named capabilities. A session is accepted only when a common version exists and every required capability is present in the intersection.

This avoids silent downgrade and makes incompatibility explicit.

## Policy passports

A policy passport is a portable, hash-bound declaration of a subject's selected profile and preferences. It may include an expiration time. The current reference implementation does not claim identity proof; it proves only integrity of the passport object itself.

## Content-addressed bundles

A bundle binds named artifacts to SHA-256 digests and derives a root digest from the sorted index. This allows transport, caching, deduplication, and post-transfer integrity verification without trusting file names or delivery order.

## Selective disclosure

A holder can disclose selected committed claims while keeping other claim values hidden. Hidden claims are represented by their leaf hashes. This is a commitment/inclusion mechanism, not a zero-knowledge proof system and must not be described as one.

## Wire protocol

Cross-system messages use a versioned envelope with:

- `protocol`;
- `version`;
- `kind`;
- advertised `capabilities`;
- `payload`.

Message kinds may include execution receipts, policy packs, policy passports, audit checkpoints, and future AML-native artifacts.

## Security properties

The current primitives provide deterministic negotiation and integrity checking. They do not provide confidentiality, authentication, identity proof, authorization, transport encryption, or semantic truthfulness by themselves.

## Design principle

> Interoperability must fail explicitly, not silently degrade accountability.

## Reference implementation

- `runtime/capabilityNegotiation.js`
- `runtime/policyPassport.js`
- `runtime/contentAddressedBundle.js`
- `runtime/selectiveDisclosure.js`
- `protocol/wireProtocol.js`
- `schema/policy-passport.schema.json`
- `schema/wire-envelope.schema.json`
