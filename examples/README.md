# ĀML™ Example Gallery

These examples are intended to be compiled with the current ĀML compiler and inspected through the emitted AST, Abstract Meaning Tree, browser output, and render decision artifacts.

## Quick run

```bash
node bin/aml.js compile examples/simple.aml dist/simple
```

Then inspect:

```text
dist/simple/index.html
dist/simple/tokens.json
dist/simple/ast.json
dist/simple/amt.json
dist/simple/render_decision.json
```

## Examples

| Example | Research purpose |
|---|---|
| `simple.aml` | Minimal EthicalRenderGate™ pass |
| `transmission-061.aml` | Flagship transmission |
| `ethical_ads.aml` | Policy-aware advertising experiment |
| `focus_mode.aml` | Focus-preserving interface |
| `social_feed.aml` | Attention-aware feed experiment |
| `learning_mode.aml` | Deep-learning interface |
| `accessibility_first.aml` | Reduced cognitive competition |
| `ai_assistant_response.aml` | Inspectable AI-generated response contract |
| `calm_checkout.aml` | Low-pressure transaction interface |

## What to inspect

For each program, compare the source declarations against the generated `amt.json` and `render_decision.json`.

The important question is not only whether the browser output appears. The important question is whether the project preserves enough declared meaning to explain why it appeared.

## Build your own

Start from `simple.aml` and change:

- `value`
- `purpose`
- `memory_role`
- `user_effect`
- `attention_cost`
- `restoration_value`

Then compile again and compare the resulting accountability artifacts.

Live lab: https://aruintelligence.github.io/aml-core/

Repository: https://github.com/aruintelligence/aml-core
