# ĀML Core v1.1.0

ĀML v1.1.0 moves the project from an executable compiler prototype toward a reproducible, inspectable developer toolchain for meaning-native interfaces.

## Major additions

### Compiler + language

- Pure in-memory `compileSource()` API
- Reproducible decision timestamps
- Simple structured comparison expressions (`>`, `>=`, `<`, `<=`, `=`, `==`, `!=`)
- Expanded runnable example suite
- Browser compiler with Node/browser parity tests

### Accountability + integrity

- Render Decision JSON Schema
- Canonical allow/suppress conformance fixtures
- Independent replication protocol
- SHA-256 `build_manifest.json` emitted with filesystem builds
- `verifyBuildManifest()` API
- `aml verify` CLI command
- Automated post-build tamper detection

### Developer tooling

The CLI now supports:

```text
aml compile
aml validate
aml inspect
aml explain
aml lint
aml verify
```

Additional tooling includes:

- semantic diagnostic codes `AML001`–`AML005`
- machine-readable `AML_CAPABILITIES.json`
- compiler benchmark harness
- VS Code `.aml` language definition and syntax highlighting
- shared completion + hover language-intelligence API
- dependency-free `aml-lsp` stdio Language Server Protocol implementation

### Browser experience

- Interactive AML source playground
- Tokens, AST, Abstract Meaning Tree, and render-decision inspection in-browser
- Live EthicalRenderGate™ laboratory

## Verify this release

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install
npm test
node bin/aml.js compile examples/simple.aml dist/simple
node bin/aml.js verify dist/simple/build_manifest.json
node bin/aml.js explain examples/simple.aml
AML_BENCH_ITERATIONS=25 npm run benchmark
```

Browser playground:

https://aruintelligence.github.io/aml-core/playground.html

Live lab:

https://aruintelligence.github.io/aml-core/

## Scope and evidence boundary

ĀML remains a research prototype. Its current attention-cost and restoration-value fields are explicit model inputs, not validated measurements of cognition, ethics, harm, restoration, or wellbeing. The v1.1 release strengthens inspectability, reproducibility, tooling, and falsifiability; it does not convert the prototype policy model into an empirical universal standard.

## Stewardship

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**

Code is MIT licensed. ĀML™, ĀRU Meaning Language™, EthicalRenderGate™, Meaning-Native Computing™, and related claimed marks remain separate from the code license.
