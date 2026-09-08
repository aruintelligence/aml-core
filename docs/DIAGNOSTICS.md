# ĀML™ Semantic Diagnostics

ĀML distinguishes syntax validity from semantic completeness. A file may parse successfully while still omitting information expected from a meaning-bearing interface node.

Run:

```bash
node bin/aml.js lint examples/simple.aml
```

or:

```bash
npm run lint
```

## Diagnostic codes

| Code | Level | Meaning |
|---|---|---|
| `AML001` | warning | Meaning-bearing node has no declared `purpose` |
| `AML002` | warning | Meaning-bearing node has no numeric `attention_cost` |
| `AML003` | error | `attention_cost` is outside the v1 range of 0–10 |
| `AML004` | warning | Meaning-bearing node has no numeric `restoration_value` |
| `AML005` | error | `restoration_value` is outside the v1 range of 0–10 |

## Why warnings and errors differ

Missing metadata is currently a warning because the prototype still needs to parse and inspect incomplete research programs. Out-of-range policy values are errors because the v1 scoring model explicitly defines a 0–10 input range.

The diagnostic policy can become stricter in later language profiles without changing the parser itself.

## Programmatic use

```js
import { analyzeAMT, compileSource } from "./index.js";

const compiled = compileSource(source);
const diagnostics = analyzeAMT(compiled.amt);
```

This lets editors, CI systems, AI authoring tools, and future language servers surface AML-specific semantic guidance without scraping terminal text.
