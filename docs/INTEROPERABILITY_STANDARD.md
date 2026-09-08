# ĀML Interoperability Standard Surface

ĀML is being pushed beyond a single reference compiler toward a protocol that independent runtimes can exchange and verify.

## What is implemented now

### Runtime negotiation

`negotiateCapabilities()` and `negotiateWireSession()` make compatibility explicit. A runtime can require capabilities such as receipts, policy passports, selective disclosure, accessibility context, or audit support and refuse a session when the peer cannot provide them.

### Portable policy passports

`createPolicyPassport()` binds a policy profile and preference set to a SHA-256 digest. Passports can expire and can be converted into runtime policy context.

This is not identity verification. Identity and authorization remain separate layers.

### Content-addressed AML bundles

`createContentAddressedBundle()` binds named artifacts to hashes and derives a deterministic root. A receiver can verify each artifact and the bundle root after transfer.

Potential uses include execution receipts, policy packs, compiled AML artifacts, research fixtures, and distributed caches.

### Selective disclosure

`createDisclosureCommitment()`, `discloseClaims()`, and `verifyDisclosureProof()` allow a holder to reveal selected committed claims while withholding the values of other claims.

The current mechanism is a hash commitment/inclusion proof. It is deliberately **not** described as zero knowledge.

### AML wire envelopes

`createWireEnvelope()` wraps a typed payload in an explicit protocol/version/capability header. This creates a stable boundary for future cross-runtime transport.

## Why this matters

A standard becomes much more credible when two independently written systems can:

1. discover what each other supports;
2. reject unsafe downgrade;
3. exchange a versioned artifact;
4. verify its integrity;
5. reveal only the minimum policy information necessary;
6. produce an inspectable receipt afterward.

## Long-term direction

A mature AML ecosystem could support browser runtimes, servers, agents, operating systems, assistive technologies, enterprise policy engines, and user-owned policy stores that all negotiate the same accountability contracts.

The present implementation is an experimental reference layer, not an established industry standard.
