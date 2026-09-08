# RFC 0001 — Abstract Meaning Tree

**Status:** Implemented

## Summary

The Abstract Meaning Tree (AMT) is the semantic representation produced after parsing ĀML source. It preserves information that ordinary syntax trees do not necessarily make first-class: declared purpose, attention cost, restoration value, privacy/consent declarations, accessibility metadata, and other meaning-bearing fields.

## Motivation

Text diffs and DOM trees describe structure. ĀML needs a stable representation that can be inspected by policy engines, semantic diff tools, accessibility audits, and execution-receipt tooling.

## Requirements

1. AMT generation must be deterministic for identical parsed input.
2. Meaning-bearing properties must remain machine readable.
3. Policy evaluation must consume declared semantics rather than scraping rendered HTML.
4. Semantic diff tooling must compare AMT state, not only source text.
5. Unknown semantic blocks should remain representable rather than being silently discarded.

## Security and evidence boundary

An AMT preserves declarations; it does not prove those declarations are truthful. Provenance, signatures, policy enforcement, and external validation are separate concerns.

## Conformance

A conforming implementation should emit an AMT for canonical fixtures and preserve the meaning-bearing fields used by the reference conformance suite.