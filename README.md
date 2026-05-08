# ĀML v1.0 — ĀRU Meaning Language

## The first rendering system that asks:

# “Should this exist?”

Traditional HTML renders anything that exists.

ĀML evaluates every interface element through an ethical rendering gate before allowing it into the final experience.

> HTML renders what exists.  
> ĀML renders what deserves to exist.
> 
# ĀML™

### The first rendering system that asks:
## “Should this exist?”

[ Try the Live Demo ](https://aruintelligence.github.io/aml-core/)
---

# Core Breakthrough — EthicalRenderGate

```aml
render_allowed = restoration_value >= attention_cost
```

Every renderable element is evaluated according to:

- attention_cost
- restoration_value
- rendering_mode
- fallback behavior
- suppression thresholds

If an element consumes more attention than the value it restores, AML can:

- suppress it
- degrade it
- reroute it
- replace it
- log the render decision transparently

This transforms rendering into an accountable semantic process.

---

# Why ĀML Exists

Modern systems optimize for:

- clicks
- engagement
- retention
- stimulation
- interruption
- emotional extraction

ĀML explores a different question:

> What if interfaces optimized for restoration instead?

AML introduces:

- accountable rendering
- restoration-aware interfaces
- semantic rendering logic
- cognitive respect layers
- transparent render decisions

---

# Live Demo

https://aruintelligence.github.io/aml-core/

The live prototype demonstrates:

- real-time EthicalRenderGate evaluation
- traditional HTML vs AML comparison
- per-element restoration controls
- degraded rendering states
- live render_decision.json output
- suppression behavior
- accountable rendering logic

---

# Example AML Syntax

```aml
transmission "simple-demo" {

  title:
    "Hello from AML"

  engram clarityCard {

    value:
      "This element restores more than it consumes."

    purpose:
      "demonstrate EthicalRenderGate"

    attention_cost:
      2

    restoration_value:
      8

  }

}
```

---

# Compiler Pipeline

```text
AML Source
   ↓
Lexer
   ↓
Parser
   ↓
Abstract Syntax Tree (AST)
   ↓
Abstract Meaning Tree (AMT)
   ↓
EthicalRenderGate
   ↓
Render Decision
   ↓
HTML Output
```

---

# Render States

| State | Meaning |
|---|---|
| allowed | fully rendered |
| degraded | partially rendered |
| suppressed | blocked by EthicalRenderGate |
| fallback | rerouted safer render path |
| mirrored | reflective semantic state |

---
## Compile AML

```bash
node compiler/aml-compiler.js examples/simple.aml dist
```

Outputs:

- dist/index.html
- dist/render_decision.json
```
# render_decision.json

AML generates transparent rendering metadata.

Example:

```json
{
  "element": "rage_bait_post",
  "attention_cost": 8.7,
  "restoration_value": 2.1,
  "render_allowed": false,
  "rendering_mode": "suppressed"
}
```

Rendering becomes observable and accountable.

---

# Repository Structure

```text
/bin
/compiler
/demo
/dist
/docs
/examples
/runtime
```

---

# Core Philosophy

Traditional systems ask:

> Can this render?

ĀML asks:

> Should this render?

This shifts rendering from:

- passive execution
to
- accountable semantic evaluation

---

# Status

ĀML v1.0 is currently:

- a conceptual rendering language
- an ethical rendering prototype
- a semantic interface framework
- a live interactive demonstration
- an experimental compiler architecture
- a research system exploring accountable computation

---

# Created By

Daniel Jacob Read IV

Stewarded by ĀRU Intelligence Inc.

---

# License

MIT
