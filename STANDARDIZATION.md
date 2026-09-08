# ĀML Standardization Path

ĀML is not currently an industry standard. It is a working research prototype and reference implementation. This document defines the evidence and engineering milestones required before stronger standardization claims would be appropriate.

## Stage 0 — Reference implementation

Requirements:

- parser/compiler/runtime exist;
- behavior is covered by automated tests;
- language and accountability artifacts are documented;
- non-claims and evidence boundaries are explicit.

Status: active.

## Stage 1 — Stable protocol contracts

Requirements:

- versioned wire envelope;
- protocol discovery document;
- identifier/media-type registry;
- canonical serialization vectors;
- JSON Schemas for public artifacts;
- compatibility levels;
- backwards-compatibility rules.

Status: active.

## Stage 2 — Independent implementation

Requirements:

- at least one implementation that does not import `aml-core` internals;
- published test results against canonical fixtures;
- documented disagreements/ambiguities;
- protocol vectors reproduced independently.

Status: open challenge in GitHub issues.

## Stage 3 — Interoperability proof

Requirements:

- two independent runtimes negotiate a wire session;
- exchange policy-passport/capability artifacts;
- verify content-addressed bundles;
- validate execution receipts;
- preserve causal execution history;
- reject incompatible versions/capabilities;
- pass replay/tamper tests.

## Stage 4 — Security maturity

Requirements:

- external threat-model review;
- canonicalization/signature review;
- replay/downgrade analysis;
- trust-root/key-rotation design;
- fuzzing/adversarial fixtures;
- vulnerability reporting process;
- regression tests for discovered failures.

## Stage 5 — Candidate specification

Requirements:

- accepted core RFC set;
- implementation-independent specification text;
- normative terminology (`MUST`, `SHOULD`, `MAY`);
- versioned conformance suite;
- at least two interoperable implementations;
- migration policy for breaking changes;
- documented governance process.

## Stage 6 — External standards engagement

Possible future paths may include discussion with relevant standards, accessibility, web-platform, AI-safety, or developer-tooling communities. Any such engagement should happen only after AML has independent implementations and reproducible interoperability evidence.

This repository must not imply endorsement by W3C, WHATWG, IETF, ISO, IEEE, NIST, browser vendors, accessibility organizations, or regulators unless such endorsement actually exists.

## Success criterion

ĀML becomes credible as a standard candidate when a skeptical engineer can implement the public contracts without reading the reference implementation, exchange artifacts with another runtime, and independently verify the resulting behavior.
