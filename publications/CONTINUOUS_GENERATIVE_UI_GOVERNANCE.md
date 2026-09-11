# ĀML now governs generated interfaces while they are still arriving

Most interface-governance approaches evaluate a finished object. ĀML now has a project-defined continuous governance stream that can evaluate semantic interface nodes one at a time across a process boundary.

The generator does not need to finish the page first.

The host does not need to trust the generator to self-police.

The governance process can sit between generation and rendering for the life of the stream.

The protocol uses NDJSON and four core messages:

- `aml-governance-stream-open/1`
- `aml-governance-stream-node/1`
- `aml-governance-stream-decision/1`
- `aml-governance-stream-finalize/1`

A final `aml-governance-stream-result/1` summarizes the session.

The reference implementation ships as:

```bash
npm run governance-stream
```

and as an HTTP streaming gateway:

```bash
npm run governance-stream:serve
```

Endpoint:

```text
POST /v1/governance/stream
Content-Type: application/x-ndjson
```

Each submitted node can receive an ALLOW/SUPPRESS result before later nodes arrive. Duplicate identifiers are rejected across the session, and a truncated stream is not silently promoted to a finalized result.

## The architectural shift

The earlier Agent UI gateway proved that generated components could cross a process boundary for governance before rendering.

The continuous stream pushes the boundary further: the governance layer can remain present during incremental interface construction rather than acting only after a complete envelope exists.

That creates a clean research surface for agentic UI systems that stream, progressively reveal, or continuously mutate human-facing interfaces.

## Claim boundary

This is a shipped project technical milestone, not a claim of independent validation, native compatibility with an external generative-UI protocol, distributed stream semantics, production security, or industry-standard status.

The strongest next evidence would be an independent runtime or external UI protocol adapter that sends its own live component stream through the published contract and reports PASS, FAIL, or MIXED.
