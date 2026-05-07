# CLI.md

# ĀML CLI Guide

The ĀML CLI provides command-line access to the AML compiler pipeline.

It allows developers to compile `.aml` source files into:
- HTML
- tokens.json
- ast.json
- amt.json
- render_decision.json

---

# Install

Clone the repository:

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
```

Install dependencies:

```bash
npm install
```

---

# Compile

Run the default compiler:

```bash
npm run compile
```

This compiles:

```text
examples/transmission-061.aml
```

into:

```text
dist/
```

---

# Direct Node Usage

You can also run the compiler directly:

```bash
node compiler/compiler.js examples/transmission-061.aml dist
```

---

# AML Command

The package registers an AML binary:

```bash
aml
```

Supported commands:

```bash
aml compile <file.aml> [outputDir]
aml help
aml version
```

Example:

```bash
aml compile examples/transmission-061.aml dist
```

---

# Output Files

After compilation, AML generates:

```text
dist/index.html
dist/tokens.json
dist/ast.json
dist/amt.json
dist/render_decision.json
```

---

# EthicalRenderGate Output

Every renderable AML element produces a render decision:

```json
{
  "attention_cost": 3,
  "restoration_value": 9,
  "render_allowed": true,
  "fallback_triggered": false
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
Abstract Syntax Tree
   ↓
Abstract Meaning Tree
   ↓
EthicalRenderGate
   ↓
HTML + JSON output
```

---

# Current Status

The CLI is an early prototype.

Current commands are intentionally minimal:
- compile
- help
- version

Future commands may include:
- inspect
- audit
- explain
- validate
- serve

---

# Created By

Daniel Jacob Read IV  
Stewarded by ĀRU Intelligence Inc.
