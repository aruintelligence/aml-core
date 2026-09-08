# Meaning-Native Computing with ĀML™

ĀML™ — ĀRU Meaning Language™ — explores a simple architectural shift: interface elements should carry declared meaning and policy inputs before they become browser output.

Traditional web stacks are excellent at describing structure, style, behavior, and data flow. They are much weaker at expressing *why* an interface element exists, what purpose it serves, what attention it consumes, and what decision process allowed it to appear.

ĀML introduces an inspectable semantic layer between authored intent and rendered output.

## The basic pipeline

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
HTML/CSS/JS + decision artifacts
```

The current implementation still targets browser-compatible HTML. The experimental contribution is the meaning-and-accountability layer that comes first.

## Why this matters

A meaning-native interface can make important assumptions explicit:

- purpose
- declared value
- attention cost
- restoration value
- policy outcome
- render mode
- reason for degradation or suppression

That creates a path toward interfaces that are easier to inspect, audit, test, and challenge.

## Current research boundary

ĀML does not claim that its present numerical inputs objectively measure human attention, wellbeing, ethics, or restoration. The current model is deliberately simple and inspectable so the architecture can be tested before stronger empirical models exist.

The project asks a narrower, executable question:

> What changes when an interface must explain why it deserves to render?

## Try it

Run the live laboratory:

https://aruintelligence.github.io/aml-core/

Source:

https://github.com/aruintelligence/aml-core

Created by Daniel Jacob Read IV and stewarded by ĀRU Intelligence Inc.™
