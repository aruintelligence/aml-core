# ĀML™ JavaScript API

The AML package now exposes a small public JavaScript API in addition to the command-line interface.

## Import

```js
import { compileAML, ethicalRenderGate } from "./index.js";
```

## `compileAML(inputPath, outputDir)`

Compiles an AML source file and writes the browser and accountability artifacts.

```js
const result = compileAML("examples/simple.aml", "dist/simple");

console.log(result.ast);
console.log(result.amt);
console.log(result.renderDecisions);
```

The returned object contains:

- `input`
- `output`
- `tokens`
- `ast`
- `amt`
- `renderDecisions`
- `html`

The compiler also emits:

```text
index.html
tokens.json
ast.json
amt.json
render_decision.json
```

## `ethicalRenderGate(element)`

Runs the current baseline EthicalRenderGate™ model against an input object.

```js
const decision = ethicalRenderGate({
  animation_intensity: 1,
  cognitive_load: 2,
  interaction_interruptions: 1,
  reading_complexity: 3,
  visual_noise: 1,
  clarity: 9,
  usefulness: 8,
  emotional_regulation: 8,
  continuity: 8,
  aesthetic_coherence: 7
});

console.log(decision.render_allowed);
console.log(decision.attention_cost);
console.log(decision.restoration_value);
```

The current model is an inspectable research baseline, not a scientifically validated universal ethics metric.

## Why expose an API?

A library surface makes AML usable inside test harnesses, build systems, AI interface pipelines, research experiments, and future integrations without shelling out to the CLI.

## Other entry points

- CLI: `bin/aml.js`
- Quickstart: `QUICKSTART.md`
- Examples: `examples/README.md`
- Replication: `REPLICATION_PROTOCOL.md`
- Live lab: https://aruintelligence.github.io/aml-core/
