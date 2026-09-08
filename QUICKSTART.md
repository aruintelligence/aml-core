# ĀML™ Quickstart

Get from clone to an inspectable render decision in a few commands.

## What ĀML is

ĀML™ — ĀRU Meaning Language™ — is a meaning-native interface language and working research prototype. The current compiler preserves declared interface meaning, evaluates it through EthicalRenderGate™, and emits browser-compatible output plus accountability artifacts.

> Every element should be able to explain why it deserves the attention it consumes.

## Requirements

- Node.js 18+
- Git

## 1. Clone

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
```

## 2. Verify the project

```bash
npm test
```

## 3. Compile the smallest example

```bash
node bin/aml.js compile examples/simple.aml dist/simple
```

## 4. Inspect the outputs

```text
dist/simple/index.html
dist/simple/tokens.json
dist/simple/ast.json
dist/simple/amt.json
dist/simple/render_decision.json
```

The important result is not only `index.html`. Compare the source program with `amt.json` and `render_decision.json` to see which declared meaning survived compilation and why the gate allowed, degraded, or suppressed output.

## 5. Change the policy inputs

Open `examples/simple.aml` and experiment with:

```aml
attention_cost:
  2

restoration_value:
  8
```

Compile again and compare the resulting decision artifact.

The current baseline gate is intentionally simple:

```text
render_allowed = restoration_value ≥ attention_cost
```

The values are declared model inputs, not validated measurements of human wellbeing or attention.

## 6. Try real interface domains

```bash
node bin/aml.js compile examples/ai_assistant_response.aml dist/ai-assistant
node bin/aml.js compile examples/learning_mode.aml dist/learning
node bin/aml.js compile examples/accessibility_first.aml dist/accessibility
node bin/aml.js compile examples/calm_checkout.aml dist/checkout
```

Additional experiments live in [`examples/`](examples/README.md).

## Mental model

```text
ĀML source
   ↓
lexer + parser
   ↓
Abstract Syntax Tree
   ↓
Abstract Meaning Tree
   ↓
EthicalRenderGate™
   ↓
HTML + decision artifacts
```

ĀML does not claim browsers have stopped using HTML. The present innovation is the inspectable semantic-policy layer before browser rendering.

## Go deeper

- [Example gallery](examples/README.md)
- [Language specification](LANGUAGE_SPEC.md)
- [Architecture](ARCHITECTURE.md)
- [Ethical rendering](ETHICAL_RENDERING.md)
- [Testing](TESTING.md)
- [Open research program](docs/RESEARCH_PROGRAM.md)
- [Live EthicalRenderGate™ Lab](https://aruintelligence.github.io/aml-core/)

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**
