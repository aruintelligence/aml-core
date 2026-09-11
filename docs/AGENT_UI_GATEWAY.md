# ĀML Agent UI Governance Gateway

This gateway exposes the project-defined Agent UI governance boundary over ordinary JSON, CLI, and HTTP so a renderer, agent runtime, or non-JavaScript system can call ĀML without importing the JavaScript adapter directly.

It is protocol-neutral. It does **not** claim native compatibility with MCP Apps, A2UI, OpenUI, or another external protocol.

## Contracts

Input:

- `aml-agent-ui-envelope/1`
- schema: `schemas/agent-ui-envelope.schema.json`

Output:

- `aml-agent-ui-governance-result/1`
- schema: `schemas/agent-ui-result.schema.json`

Golden vector:

- `conformance/agent-ui/mixed.json`

## CLI

```bash
npm run agent-ui
```

Or evaluate any envelope:

```bash
aml-agent-ui path/to/envelope.json --profile calm_default --mode enforce --timestamp 2026-09-10T00:00:00.000Z
```

Use `-` or omit the file to read JSON from standard input.

## HTTP gateway

```bash
npm run agent-ui:serve
```

Default endpoint:

```text
POST http://127.0.0.1:8790/v1/agent-ui/evaluate
```

## Why this matters

The governance contract is no longer limited to an in-process JavaScript function. A separate process can hand over generated components before rendering and receive a deterministic governance result containing renderable and suppressed component sets plus decision evidence.

That makes the boundary suitable for future adapters in other languages or UI protocols without requiring those systems to adopt ĀML's internal implementation.

## Evidence boundary

The gateway, schemas, golden vector, CLI, and tests are project-controlled engineering evidence. They demonstrate a shipped cross-process contract inside the ĀML prototype. They do not establish external adoption, independent implementation, production suitability, protocol-standard status, certification, or endorsement.
