# ĀML Governance

ĀML is currently stewarded by ĀRU Intelligence Inc. and remains a research prototype. Governance exists to move ĀML toward an independently implementable, testable standard rather than a single-vendor codebase.

## Principles

1. **Specification and implementation are separate.** `aml-core` is the reference implementation, not the definition of correctness by itself.
2. **Compatibility claims must be testable.** Published conformance fixtures, protocol vectors, and compatibility levels are the basis for interoperability claims.
3. **Breaking changes require versioning.** Wire identifiers, schemas, registry entries, and accepted RFCs must not change silently.
4. **Independent implementations are encouraged.** A useful independent runtime may expose ambiguity or flaws in the reference implementation.
5. **Dissent is evidence.** Security failures, policy disagreements, accessibility findings, and interoperability mismatches should result in documented issues and regression tests.
6. **Integrity is not morality.** Hashes and signatures prove integrity/key possession, not truth, ethics, legality, wellbeing, or accessibility.
7. **Human-impact claims require evidence.** Present attention/restoration values are declared model inputs, not validated universal measurements of cognition or wellbeing.

## RFC lifecycle

**Draft → Experimental → Candidate → Accepted → Superseded/Withdrawn**

A Candidate RFC should have:

- a reference implementation;
- reproducible tests or protocol vectors;
- security considerations;
- compatibility and migration notes;
- at least one independent review.

An interoperability RFC should not become Accepted until at least one independent implementation or protocol peer demonstrates compatible behavior.

## Registry governance

Stable protocol identifiers live in `protocol/registry.json`.

Changes to stable media-type candidates, wire versions, message kinds, or required conformance capabilities should:

- be proposed through an RFC or explicit registry-change issue;
- preserve existing identifiers unless a new version is introduced;
- include discovery/registry consistency tests;
- document backwards compatibility;
- avoid reusing an old identifier for new semantics.

High-impact future governance actions may use ĀML threshold-authorization primitives so multiple distinct keys are required to approve a registry or policy change. The repository does **not** claim that governance is already decentralized.

## Compatibility levels

Compatibility levels are defined in `conformance/levels.json` and RFC 0008.

An implementation should identify the exact:

- AML language/spec version;
- wire version;
- conformance level;
- implementation/version;
- reproducible test artifact or test date.

Compatibility must not imply endorsement, regulatory approval, or certification of ethical behavior.

## Security governance

Security-relevant changes should include:

- threat model impact;
- replay/tamper considerations;
- canonicalization/signature impact;
- trust-root or delegation impact;
- protocol downgrade considerations;
- regression tests when practical.

Public adversarial review is encouraged. Sensitive vulnerabilities should use the repository security-reporting path rather than public disclosure before remediation.

## Reference implementation

`aruintelligence/aml-core` is the current reference implementation. Independent implementations MUST NOT be required to import its internal modules to claim compatibility.

## Marks and licensing

Code licensing and claimed marks are separate. Any future “ĀML Compatible” mark should communicate only compliance with published technical requirements.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**.
