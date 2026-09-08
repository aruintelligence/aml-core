# RFC 0008 — AML Compatibility Levels

Status: Draft

## Abstract

This RFC defines layered AML interoperability claims so compatibility can be tested rather than implied.

## Levels

### AML Core Compatible

Requires support for:

- meaning-tree
- render-decision

### AML Accountable Compatible

Extends Core and requires:

- execution-receipt
- view-meaning

### AML Federated Compatible

Extends Accountable and requires:

- policy-passport
- content-addressed-bundle
- causal-execution-graph

### AML Verifiable Compatible

Extends Federated and requires:

- selective-disclosure

### AML Governed Compatible

Extends Verifiable and requires:

- bounded-capability-token
- proof-carrying-interface
- revocation-registry

This level is intended for systems where authority must be bounded, evidence must travel with rendered output, and previously trusted artifacts must be revocable.

## Rules

An implementation MUST NOT claim a level unless all requirements for that level and inherited levels pass the published conformance suite or an equivalent independently reproducible suite.

A compatibility claim MUST identify:

- AML language/specification version
- wire version
- conformance level
- implementation/version
- test date or immutable test artifact

## Purpose

The levels separate minimal language interoperability from stronger accountability, federation, verification, and governance guarantees. They also give independent implementations a realistic adoption path without requiring every AML feature on day one.
