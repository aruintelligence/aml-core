# ĀML crosses the generated-interface process boundary

ĀML now exposes a protocol-neutral governance contract that can be called from outside the JavaScript runtime before generated interface components are rendered.

The shipped project surfaces are:

- `evaluateAgentUI(...)` for in-process JavaScript use;
- `aml-agent-ui` for command-line evaluation;
- `aml-agent-ui-serve` for a standalone HTTP governance service;
- `POST /v1/agent-ui/evaluate` for JSON-over-HTTP evaluation;
- machine-readable input and output schemas;
- a golden mixed ALLOW/SUPPRESS conformance vector.

The practical architecture is:

```text
agent / model / UI generator
          |
          v
aml-agent-ui-envelope/1
          |
          v
ĀML governance process
          |
          +--> renderable components
          |
          +--> suppressed components
          |
          +--> decision evidence
          v
renderer / host application
```

This matters because the renderer does not need to trust the generator to govern itself, and the generator does not need to own the policy implementation. The governance decision can be delegated to a separate process with an explicit JSON contract.

Run the golden vector:

```bash
npm run agent-ui
```

Run the gateway:

```bash
npm run agent-ui:serve
```

Then POST an `aml-agent-ui-envelope/1` document to:

```text
http://127.0.0.1:8790/v1/agent-ui/evaluate
```

The returned `aml-agent-ui-governance-result/1` separates renderable and suppressed components and carries per-component decision evidence.

## Claim boundary

This is a shipped ĀML research-prototype milestone. It does not claim external protocol adoption, compatibility certification, production suitability, or independent validation. In particular, it does not claim native MCP Apps, A2UI, OpenUI, or other third-party protocol compatibility.

The next meaningful proof is outside this repository: another runtime or protocol adapter independently targeting the published JSON boundary and reporting PASS, FAIL, or MIXED.
