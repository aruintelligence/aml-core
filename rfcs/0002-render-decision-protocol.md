# RFC 0002 — Render Decision Protocol

**Status:** Implemented

## Summary

Every meaning-bearing interface node evaluated by ĀML can emit a render decision describing the policy used, declared values, runtime context relevant to the decision, allow/suppress outcome, and rationale.

## Motivation

A render outcome without an explanation is difficult to audit. ĀML treats the decision record as a first-class artifact so tooling can inspect, compare, validate, and sign it.

## Required fields

A decision should identify the node, policy identity, `render_allowed`, rationale, and the declared or derived values used by that policy. Implementations may add fields but should not silently change the meaning of existing protocol fields.

## Policy identity

Policy identity is part of the decision. The same source evaluated under a different policy can legitimately produce a different outcome; the record must make that distinction explicit.

## Security

Decision records are claims about execution state. Integrity mechanisms such as SHA-256 manifests, execution receipts, and Ed25519 attestations can bind those claims to artifacts, but signatures do not prove a policy is morally correct or empirically valid.

## Conformance

Canonical allow and suppress fixtures must produce machine-readable decisions that can be validated by the published decision schema.