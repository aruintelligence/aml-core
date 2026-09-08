# ĀML™ Render Decision Protocol

Every ĀML compilation can emit `render_decision.json`: a machine-readable accountability artifact describing which meaning-bearing nodes were evaluated, which policy produced the decision, and whether the node was allowed to render.

The canonical schema is [schema/render-decision.schema.json](../schema/render-decision.schema.json).

## Current decision surface

Depending on the active compiler/runtime path, a decision can include fields such as:

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
- `policy_id`
- `policy_rationale`
- `render_allowed`
- `fallback_triggered`
- `timestamp`

The JSON Schema is the machine-readable source of truth for the serialized protocol.

## Declared versus calculated values

ĀML preserves the distinction between authored semantic values and values calculated by a policy/runtime model. Missing values must not be silently treated as explicit zero values.

## Baseline policy

The baseline `restorative_v1` policy uses the intentionally simple relationship:

```text
render_allowed = restoration_value >= attention_cost
```

Other v1.2 policy engines can make different decisions from the same meaning-bearing source. The decision record therefore identifies the policy rather than implying that one gate is universal.

## Reproducible inspection

```bash
node bin/aml.js inspect examples/ai_assistant_response.aml
```

For emitted artifacts:

```bash
node bin/aml.js compile examples/ai_assistant_response.aml dist/ai-assistant
cat dist/ai-assistant/render_decision.json
node bin/aml.js verify dist/ai-assistant/build_manifest.json
```

For counterfactual policy comparison:

```bash
node bin/aml.js simulate examples/ai_assistant_response.aml restorative_v1,attention_conservative_v1
```

## Accountability property

The visible interface is only one result of compilation. ĀML treats the decision record as a first-class artifact so downstream systems can ask not only **what rendered**, but **which declared inputs and policy produced that outcome**.

The current policies are research prototypes, not scientifically validated universal measures of ethics, attention, restoration, or wellbeing.
