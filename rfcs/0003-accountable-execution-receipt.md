# RFC 0003 — Accountable Execution Receipt

**Status:** Implemented

## Summary

The Accountable Execution Receipt binds the major stages of an ĀML execution into one verifiable record: original intent, generated ĀML, policy simulations, selected policy/profile, final decisions, runtime context, output, and integrity hashes.

## Goals

- make AI-to-interface execution auditable after the fact;
- distinguish proposed intent from approved output;
- provide a stable object for View Meaning™;
- support detached cryptographic attestation;
- support provenance graphs and Merkle batching.

## Integrity

Receipt verification recomputes canonical hashes and fails when protected content changes. Optional Ed25519 signatures attest that a key signed that receipt state.

## Privacy

Receipts should contain only the context required for accountability. Systems embedding ĀML must avoid turning receipts into unnecessary surveillance logs. Selective disclosure and minimization are future protocol priorities.

## Non-goals

A valid receipt does not prove the underlying declaration was truthful, the policy was wise, or the user was unharmed. It proves integrity and records the decision process implemented by the system.

## Conformance

Implementations claiming receipt compatibility should validate against the published execution-receipt schema and detect protected-field mutation.