# ĀML™ Render Decision Protocol

Every AML compilation can emit `render_decision.json`: a machine-readable accountability artifact describing which meaning-bearing nodes were evaluated and whether they were allowed to render.

The canonical JSON Schema is published at:

`schema/render-decision.schema.json`

## Required decision fields

Each decision currently records:

- `node_type`
- `name`
- `identifier`
- `purpose`
- `memory_role`
- `user_effect`
- `attention_cost`
- `restoration_value`
- `calculated_attention_cost`
- `calculated_restoration_value`
- `render_allowed`
- `fallback_triggered`
- `timestamp`

## Why define a protocol?

A compiler output becomes more useful when external systems can depend on a documented contract. The decision protocol gives test harnesses, editors, research tools, CI systems, and future policy engines a stable surface to inspect.

## Declared versus calculated values

AML currently preserves both authored values and values calculated by the prototype gate. This distinction matters because authored semantic metadata and policy-derived values should not be silently collapsed into one number.

## Accountability property

For the current prototype:

```text
render_allowed = restoration_value >= attention_cost
fallback_triggered = !render_allowed
```

This relationship is intentionally simple and inspectable. It is not presented as a validated universal ethics model.

## Reproducible inspection

```bash
node bin/aml.js inspect examples/ai_assistant.aml
```

For emitted artifacts:

```bash
node bin/aml.js compile examples/ai_assistant.aml dist/ai-assistant
cat dist/ai-assistant/render_decision.json
```

## Design principle

The visible interface is only one result of compilation. AML treats the decision record as a first-class output so downstream systems can ask not only what rendered, but why.
