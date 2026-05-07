# ARCHITECTURE.md

# ĀML Architecture

ĀML is structured as a meaning-native compiler and runtime system.

The architecture is designed to transform `.aml` source files into:
- semantic HTML
- compiler artifacts
- Abstract Meaning Trees
- render accountability logs
- EthicalRenderGate decisions

---

# High-Level System Flow

```text
AML Source (.aml)
   ↓
Lexer
   ↓
Parser
   ↓
Abstract Syntax Tree (AST)
   ↓
Abstract Meaning Tree (AMT)
   ↓
Render Evaluator
   ↓
EthicalRenderGate
   ↓
HTML Generator
   ↓
Generated Output
```

---

# Core Architectural Layers

## 1. Source Layer

The source layer contains human-readable AML files.

Example:

```aml
transmission "061" {

  engram eternalFlame {

    purpose:
      "anchor sovereign identity"

    attention_cost:
      3

    restoration_value:
      9

  }

}
```

The source layer is designed to prioritize:
- semantic readability
- low syntactic noise
- clear purpose declarations
- restoration-aware metadata

---

## 2. Lexer Layer

File:

```text
compiler/lexer.js
```

The lexer converts AML source text into tokens.

Responsibilities:
- identify keywords
- identify identifiers
- detect braces
- parse strings
- parse numbers
- preserve line and column metadata

Example token:

```json
{
  "type": "KEYWORD",
  "value": "engram",
  "line": 9,
  "column": 3
}
```

The lexer is the first deterministic transformation stage.

---

## 3. Parser Layer

File:

```text
compiler/parser.js
```

The parser converts tokens into an Abstract Syntax Tree.

Responsibilities:
- parse blocks
- parse properties
- preserve nested hierarchy
- validate structural relationships
- produce predictable AST output

Example AST node:

```json
{
  "type": "Block",
  "name": "engram",
  "identifier": "eternalFlame",
  "children": []
}
```

The parser captures structure before semantic interpretation.

---

## 4. Abstract Syntax Tree

Generated file:

```text
dist/ast.json
```

The AST represents syntactic
