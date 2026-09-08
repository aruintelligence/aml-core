# ĀML Verifier Network Direction

**Status: DRAFT protocol direction built on SHIPPED prototype primitives**

## The problem

A verifier can be detached from the page and still be wrong. A future verification ecosystem therefore needs plural implementations, explicit disagreement, portable reports, and machine-readable capability discovery.

## Shipped building blocks

- `aml-verification-report/1`
- `aml-verifier-manifest/1`
- `aml-verification-quorum/1`
- `aml-witness-record/1`
- `protocol/verifier-registry.json`
- `WITNESSES.json`
- browser, worker, Node/WebCrypto, Python, and HTTP reference verification paths

## Direction

A future verifier network should be able to:

1. discover verifier capabilities;
2. send the exact same artifact to multiple verifiers;
3. receive normalized reports;
4. reject reports about different artifact hashes;
5. preserve disagreement;
6. apply an explicit caller-selected threshold;
7. distinguish reference implementations from genuinely external implementations;
8. archive public witness evidence without inventing adoption;
9. version canonicalization and artifact contracts rather than silently changing bytes;
10. allow negative witness records when an implementation finds a real mismatch.

## Non-goals

This project does not claim that:

- majority agreement establishes truth;
- verifier IDs prove separate ownership or institutional independence;
- a quorum is certification;
- a witness registry is a standards body;
- cryptographic validity makes declared AML meaning objectively true.

## Why this matters

The useful future is not a central AML server telling everyone what is valid. It is a published contract simple enough that browsers, servers, local tools, independent projects, researchers, and enterprises can verify the same evidence themselves and compare results.

The strongest next milestone is an outside implementation producing a public `aml-verification-report/1` over the golden witness vector.
