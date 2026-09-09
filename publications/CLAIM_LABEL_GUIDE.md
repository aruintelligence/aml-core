# ĀML Claim Label Guide

**Status: SHIPPED publication rule**

Use exactly four public status labels:

- **SHIPPED** — implemented and linked to evidence.
- **SPEC** — a documented contract or standards-oriented surface; implementation coverage may vary.
- **DRAFT** — proposed material that may change.
- **PITCH** — positioning, category framing, or proposed future use; not adoption evidence.

## Examples

**SHIPPED:** “The repository contains Python and Go reference verifiers exercised through the black-box conformance harness.”

**SPEC:** “`aml-verification-report/1` defines a machine-readable result shape.”

**DRAFT:** “A health-interface casebook proposes how an interface firewall could be evaluated in that domain.”

**PITCH:** “Interface accountability could become a broadly useful category for AI-generated UI.”

## Forbidden status inflation

Do not turn:

- a DRAFT casebook into “used in health”; 
- a reference verifier into an external witness;
- a project-defined conformance level into an external certification;
- a cryptographic integrity result into a truth or safety guarantee;
- a proposed category into established market consensus.

When uncertain, use the weaker label and link `CLAIMS.md`.
