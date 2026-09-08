# ĀML™ Documentation Hub

ĀML™ — ĀRU Meaning Language™ — is a working research prototype for meaning-native, accountable interfaces. This directory collects the public research notes, explainers, tooling, and supporting material around the compiler and EthicalRenderGate™.

## Run AML now

- [AI Interface Firewall](AI_INTERFACE_FIREWALL.md) — mainstream adoption layer for AI/apps, React-compatible components, View Meaning, and CI gating
- [Browser Playground](https://aruintelligence.github.io/aml-core/playground.html) — type AML source and inspect tokens, AST, Abstract Meaning Tree, and render decisions directly in the browser
- [Live EthicalRenderGate™ Lab](https://aruintelligence.github.io/aml-core/) — interact with the policy model and compare legacy rendering with accountable rendering
- [Quickstart](../QUICKSTART.md) — clone, test, compile, validate, lint, and inspect from the terminal
- [API](API.md) — use the public JavaScript API programmatically
- [Example Gallery](../examples/README.md) — runnable AML programs across multiple interface domains
- [VS Code language support](../editors/vscode/README.md) — `.aml` recognition, syntax highlighting, comments, brackets, fields, and operators

## Start here

- [Why ĀML](WHY_AML.md)
- [Meaning-Native Computing](MEANING_NATIVE_COMPUTING.md)
- [ĀML and HTML: Different Jobs in the Stack](AML_VS_HTML.md)
- [Accountable Interfaces](ACCOUNTABLE_INTERFACES.md)
- [EthicalRenderGate™ Explained](ETHICAL_RENDER_GATE_EXPLAINED.md)
- [Open Research Program](RESEARCH_PROGRAM.md)

## Mainstream adoption

- [AI Interface Firewall](AI_INTERFACE_FIREWALL.md)
- React-compatible `AccountableUI` adapter at [`adapters/react.js`](../adapters/react.js)
- `View Meaning` inspector at [`tooling/viewMeaning.js`](../tooling/viewMeaning.js)
- Pull-request semantic gate at [`tooling/prGate.js`](../tooling/prGate.js)
- Reusable GitHub Action at [`actions/meaning-gate/action.yml`](../actions/meaning-gate/action.yml)

## Language + tooling

- [Semantic Diagnostics](DIAGNOSTICS.md)
- [Policy Expressions](POLICY_EXPRESSIONS.md)
- [Build Integrity](BUILD_INTEGRITY.md)
- [Benchmarking Protocol](BENCHMARKING.md)
- [Language specification](../LANGUAGE_SPEC.md)
- [Machine-readable capability manifest](../AML_CAPABILITIES.json)
- [Quickstart](../QUICKSTART.md)

## Protocol + proof

- [Render Decision Protocol](RENDER_DECISION_PROTOCOL.md)
- [Render Decision JSON Schema](../schema/render-decision.schema.json)
- [Conformance Manifest](../CONFORMANCE.json)
- [Independent Replication Protocol](../REPLICATION.md)
- [Testing](../TESTING.md)

The compiler supports fixed decision timestamps for reproducible builds and emits a SHA-256 build manifest. CI enforces semantic lint, canonical allow/suppress fixtures, browser/core parity, editor asset validity, reproducible builds, build-integrity hashes, CLI validation, inspectable output, and benchmark execution.

## AI + interface research

- [ĀML for AI-Generated Interfaces](AI_GENERATED_INTERFACES.md)
- [Why Machine-Readable Intent Matters](WHY_MACHINE_READABLE_INTENT.md)
- [Attention as an Interface Resource](ATTENTION_AS_A_RESOURCE.md)
- [Trust Continuity](TRUST_CONTINUITY.md)

## Core project material

- [Breakthrough](BREAKTHROUGH.md)
- [Root project README](../README.md)
- [Architecture](../ARCHITECTURE.md)
- [White paper](../WHITEPAPER.md)
- [Roadmap](../ROADMAP.md)
- [Contribution guide](../CONTRIBUTING.md)

## Core research question

> What changes when an interface must explain why it deserves to render?

The present scoring model is intentionally simple and inspectable. It is not presented as an objective measure of ethics, attention, restoration, harm, or wellbeing. The repository exists so the architecture, assumptions, and implementation can be examined and challenged.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**
