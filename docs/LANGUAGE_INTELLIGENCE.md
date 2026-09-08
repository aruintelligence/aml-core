# ĀML™ Language Intelligence

ĀML v1.1 exposes a dependency-free language-intelligence layer for editors, AI authoring tools, and future Language Server Protocol adapters.

## Public API

```js
import {
  getCompletionItems,
  getHoverInfo,
  getLanguageCatalog
} from "./index.js";
```

### Completions

```js
getCompletionItems("rest");
```

returns structured completion records such as `restoration_value`, including kind, documentation, and insertion text.

The catalog currently covers:

- core semantic blocks;
- policy and meaning properties;
- comparison operators.

### Hover information

```js
getHoverInfo("attention_cost");
```

returns the symbol kind and short documentation. Unknown symbols return `null`.

### Machine-readable catalog

```js
getLanguageCatalog();
```

returns the complete block/property/operator vocabulary as a versioned JSON-compatible object.

## Why this layer exists

Editor support should consume the same versioned language vocabulary as agents and future IDE tooling instead of each integration inventing its own terminology.

This module is deliberately transport-neutral. It can feed:

- VS Code completion providers;
- an LSP server;
- browser editors;
- AI coding agents;
- documentation generators;
- schema/tool discovery systems.

## Current boundary

This is language intelligence, not yet a full Language Server Protocol implementation. It does not currently perform document-position parsing, incremental synchronization, go-to-definition, rename, or workspace indexing.

Those features can be layered on top without changing the compiler core.
