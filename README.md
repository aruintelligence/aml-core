# ĀML™ — ĀRU Meaning Language™

## HTML asks whether it *can* render. ĀML asks whether it *should*.

[![CI](https://github.com/aruintelligence/aml-core/actions/workflows/ci.yml/badge.svg)](https://github.com/aruintelligence/aml-core/actions/workflows/ci.yml)
[![Live Lab](https://img.shields.io/badge/OPEN-LIVE_LAB-7df9ff?style=for-the-badge&labelColor=07111f)](https://aruintelligence.github.io/aml-core/)
[![Node 18+](https://img.shields.io/badge/NODE-18%2B-9cffb0?style=for-the-badge&labelColor=07111f)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/CODE-MIT-f2ce72?style=for-the-badge&labelColor=07111f)](LICENSE)

**ĀML is a working research prototype for meaning-native, accountable interfaces.** It compiles semantic intent into browser-compatible output while producing an inspectable record of why each element was allowed, degraded, or suppressed.

> The web inherited a document language from another era. Intelligent interfaces need a decision layer.

[**Launch the EthicalRenderGate™ Lab →**](https://aruintelligence.github.io/aml-core/)

[![ĀML live accountable-rendering laboratory](docs/assets/aml-live-demo.jpg)](https://aruintelligence.github.io/aml-core/)

## The shift

| Legacy HTML substrate | ĀML accountability layer |
|---|---|
| Describes what exists | Declares what an element means |
| Renders when syntax is valid | Evaluates before rendering |
| Treats attention as free | Models attention as a cost |
| Leaves intent implicit | Exposes purpose and policy inputs |
| Produces a page | Produces a page **and** a decision record |
| Answers “Can this render?” | Answers “Should this render—and why?” |

ĀML does not pretend browsers have stopped speaking HTML. Today, it compiles to HTML, CSS, JavaScript, an Abstract Meaning Tree, and accountability artifacts. The innovation is the inspectable meaning-and-policy layer before browser rendering—not a claim that the browser substrate has vanished.

## The core experiment

The current EthicalRenderGate uses an intentionally simple, inspectable rule:

```text
render_allowed = restoration_value ≥ attention_cost
```

Near-threshold failures may degrade; larger failures are suppressed. The inputs are declared model values, not clinical measurements or universal ethical truth.

```aml
transmission "deep_focus" {
  engram DeepArticle {
    value: "Long-form restorative learning."
    purpose: "Increase coherence and understanding."
    attention_cost: 3.2
    restoration_value: 9.1
  }
}
```

## What runs today

```mermaid
flowchart LR
    A[".aml source"] --> B["Lexer + parser"]
    B --> C["Meaning tree"]
    C --> D["EthicalRenderGate"]
    D --> E["HTML + decision artifacts"]
```

- Working lexer, parser, Abstract Syntax Tree, and Abstract Meaning Tree
- CLI compilation
- Importable JavaScript package API
- Allowed, degraded, and suppressed render modes
- Browser laboratory with live policy inputs
- Machine-readable `render_decision.json`
- CI-enforced compilation across the runnable example gallery
- Automated gate and end-to-end compiler smoke tests
- GitHub Actions verification on pushes and pull requests

## Run it in under a minute

Requires Node.js 18 or newer.

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm test
node bin/aml.js compile examples/simple.aml dist/simple
```

The compiler emits:

```text
dist/simple/
├── index.html
├── tokens.json
├── ast.json
├── amt.json
└── render_decision.json
```

For CLI help:

```bash
node bin/aml.js help
```

For the full developer path, read [QUICKSTART.md](QUICKSTART.md).

## Developer surface

| Surface | Use it for |
|---|---|
| [Quickstart](QUICKSTART.md) | Clone, test, compile, inspect |
| [JavaScript API](API.md) | Import `compileAML` and `ethicalRenderGate` |
| [Example gallery](examples/README.md) | Run AML across AI, learning, accessibility, commerce, feeds, focus, and ads |
| [Replication protocol](REPLICATION_PROTOCOL.md) | Independently reproduce compiler behavior |
| [Conformance manifest](conformance/manifest.json) | Machine-readable fixture and artifact contract |
| [Live Lab](https://aruintelligence.github.io/aml-core/) | Interactively inspect gate behavior |

## Proof surface

The project is structured so claims can be tested against artifacts:

```text
AML source
  ↓
tokens.json
  ↓
ast.json
  ↓
amt.json
  ↓
render_decision.json
  ↓
index.html
```

That means a reviewer can inspect not only the rendered page, but the compiler path and policy outcome that produced it.

## Inspect the system

| Start here | What it contains |
|---|---|
| [Documentation hub](docs/README.md) | Research notes and conceptual map |
| [Manifesto](MANIFESTO.md) | Why accountable rendering matters |
| [Architecture](ARCHITECTURE.md) | Compiler and runtime structure |
| [Language specification](LANGUAGE_SPEC.md) | Current syntax and semantics |
| [Ethical rendering](ETHICAL_RENDERING.md) | Gate model and boundaries |
| [Testing](TESTING.md) | Reproducible verification |
| [Roadmap](ROADMAP.md) | Planned compiler and runtime work |
| [White paper](WHITEPAPER.md) | Research framing |
| [Contribution guide](CONTRIBUTING.md) | How to challenge or improve the work |
| [Open research program](docs/RESEARCH_PROGRAM.md) | Research tracks and unanswered questions |

## What ĀML is—and is not

ĀML demonstrates an implemented semantic-policy architecture. It does **not** establish that its scores objectively measure attention, restoration, harm, ethics, or wellbeing. Those dimensions need operational definitions, empirical study, accessibility review, adversarial testing, and independent scrutiny before real-world use.

The project is best understood as an executable question:

> What changes when an interface must explain the attention it consumes?

## Build with us

Useful contributions include parser tests, malformed-input handling, accessibility work, alternate policy models, counterexamples, security review, AI-generated interface experiments, additional conformance fixtures, and empirical evaluation methods. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before submitting work.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**

Code is available under the [MIT License](LICENSE). ĀML™, ĀRU Meaning Language™, EthicalRenderGate™, Meaning-Native Computing™, and ĀRU Intelligence Inc.™ are claimed marks of ĀRU Intelligence Inc.; trademark rights are separate from the code license.
