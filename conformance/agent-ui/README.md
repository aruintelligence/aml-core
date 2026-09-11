# Agent UI governance conformance vector

`mixed.json` is the canonical project-controlled starting vector for the `aml-agent-ui-envelope/1` contract.

With profile `calm_default` and a fixed timestamp, it is expected to produce:

- total components: 2
- allowed: 1
- suppressed: 1
- renderable component id: `continue`
- suppressed component id: `pressure`

Run it through the CLI:

```bash
aml-agent-ui conformance/agent-ui/mixed.json --timestamp 2026-09-10T00:00:00.000Z
```

Or through the gateway:

```bash
npm run agent-ui:serve
```

and POST the vector as `envelope` to `/v1/agent-ui/evaluate`.

A third-party implementation reproducing this vector would be stronger interoperability evidence than this project-controlled fixture alone, but independence must be established separately.
