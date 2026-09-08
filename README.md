# ĀML™ — ĀRU Meaning Language™

## HTML asks whether it *can* render. ĀML asks whether it *should* — and now records who proposed it, which policies evaluated it, what rendered, and why.

[![CI](https://github.com/aruintelligence/aml-core/actions/workflows/ci.yml/badge.svg)](https://github.com/aruintelligence/aml-core/actions/workflows/ci.yml)
[![Playground](https://img.shields.io/badge/OPEN-AML_PLAYGROUND-7df9ff?style=for-the-badge&labelColor=07111f)](https://aruintelligence.github.io/aml-core/playground.html)
[![Live Lab](https://img.shields.io/badge/OPEN-LIVE_LAB-a994ff?style=for-the-badge&labelColor=07111f)](https://aruintelligence.github.io/aml-core/)
[![Release](https://img.shields.io/badge/RELEASE-v1.1.0-f2ce72?style=for-the-badge&labelColor=07111f)](https://github.com/aruintelligence/aml-core/releases/tag/v1.1.0)
[![Development](https://img.shields.io/badge/NEXT-v1.2.0--dev-ff9e64?style=for-the-badge&labelColor=07111f)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/CODE-MIT-9cffb0?style=for-the-badge&labelColor=07111f)](LICENSE)

**ĀML is a working research prototype for meaning-native, policy-aware, accountable interfaces.** It compiles semantic intent into browser-compatible output while preserving inspectable records of the decisions made before rendering.

> The web inherited a document language. AI-native interfaces need an accountable execution layer.

[**Launch the browser playground →**](https://aruintelligence.github.io/aml-core/playground.html)

## The v1.2 breakthrough direction

ĀML is evolving beyond a markup/compiler experiment into a boundary between **machine-generated intent** and **human-facing output**.

```mermaid
flowchart LR
    A["AI / machine intent"] --> B["Deterministic intent compiler"]
    B --> C["ĀML source"]
    C --> D["AST + Abstract Meaning Tree"]
    D --> E["Counterfactual policy simulation"]
    E --> F["User / organization policy profile"]
    F --> G["Composed policy decision"]
    G --> H["Browser-compatible output"]
    H --> I["SHA-256 execution receipt"]
    I --> J["Optional Ed25519 attestation"]
```

The AI proposes. The policy layer evaluates. The compiler records. The receipt binds the stages together.

## What runs today

### Language + compiler

- Lexer and parser for `.aml` source
- Abstract Syntax Tree and Abstract Meaning Tree
- Pure in-memory `compileSource()` API
- Filesystem `compileAML()` pipeline
- Browser compiler with Node/browser parity tests
- Simple comparison-expression parsing
- Interactive browser playground

### Accountable AI execution

- Deterministic **machine intent → ĀML** compiler
- Counterfactual simulation across multiple policy engines
- User / organization **policy profiles**
- Composed policy evaluation
- Runtime context passed into policy decisions
- `ĀML Accountable Execution Receipt`
- SHA-256 binding of intent, AML source, simulation results, decisions, and output
- Execution receipt JSON Schema
- Receipt mutation detection
- Optional **Ed25519-signed execution receipts**

### Built-in policy engines

| Policy | Current purpose |
|---|---|
| `restorative_v1` | Require restoration value ≥ attention cost |
| `attention_conservative_v1` | Require a 20% restoration margin over attention cost |
| `consent_guard_v1` | Suppress consent-gated nodes without runtime consent |
| `privacy_guard_v1` | Suppress declared personal-data collection without privacy consent |
| `session_attention_budget_v1` | Suppress nodes that exceed the remaining runtime attention budget |

### Built-in policy profiles

| Profile | Composition |
|---|---|
| `calm_default` | restoration + consent |
| `strict_attention` | conservative attention + consent + session budget |
| `privacy_first` | restoration + consent + privacy + session budget |

Profiles currently use an `all_must_allow` strategy: one denying policy is enough to suppress a node.

## The accountable execution receipt

An execution receipt can bind all of this into one machine-readable object:

```text
original intent
  ↓ SHA-256
generated AML source
  ↓ SHA-256
counterfactual policy simulations
  ↓ SHA-256
composed-policy decisions
  ↓ SHA-256
browser output
  ↓ SHA-256
execution receipt
  ↓ optional Ed25519 signature
signed accountable execution record
```

Read [Accountable AI Pipeline](docs/ACCOUNTABLE_AI_PIPELINE.md) and the [Execution Receipt JSON Schema](schema/execution-receipt.schema.json).

## CLI

```text
aml compile
aml generate
aml execute
aml verify-receipt
aml sign-receipt
aml verify-signed-receipt
aml simulate
aml policies
aml profiles
aml validate
aml inspect
aml explain
aml lint
aml verify
aml sign
aml verify-attestation
```

Example accountable flow:

```bash
node bin/aml.js execute intent.json privacy_first context.json receipt.json
node bin/aml.js verify-receipt receipt.json
node bin/aml.js sign-receipt receipt.json private-key.pem signed-receipt.json
node bin/aml.js verify-signed-receipt signed-receipt.json
```

Example runtime context:

```json
{
  "consent_granted": true,
  "privacy_consent": false,
  "attention_budget_remaining": 5
}
```

## The original EthicalRenderGate™ experiment

The baseline policy remains intentionally simple:

```text
render_allowed = restoration_value ≥ attention_cost
```

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

The values are declared model inputs. They are **not** claimed to be validated measurements of a person's cognition, ethics, attention, restoration, or wellbeing.

## Integrity + proof surface

Filesystem compilation emits:

```text
dist/example/
├── index.html
├── tokens.json
├── ast.json
├── amt.json
├── render_decision.json
└── build_manifest.json
```

The build manifest hashes the AML source and major artifacts with SHA-256. It can also receive a detached Ed25519 build attestation.

The v1.2 execution layer adds a second proof object: the accountable execution receipt, which binds AI/machine intent to generated source, policy simulation, selected decisions, and final output.

## Developer surface

| Surface | Use it for |
|---|---|
| [Browser Playground](https://aruintelligence.github.io/aml-core/playground.html) | Type AML and inspect tokens, AST, AMT, and decisions |
| [Live Lab](https://aruintelligence.github.io/aml-core/) | Operate the EthicalRenderGate™ model interactively |
| [Accountable AI Pipeline](docs/ACCOUNTABLE_AI_PIPELINE.md) | Understand intent → policy → receipt architecture |
| [Policy Profiles](docs/POLICY_PROFILES.md) | User/org-owned policy composition |
| [Quickstart](QUICKSTART.md) | Clone, test, compile, validate, lint, inspect |
| [JavaScript API](docs/API.md) | Import compiler, gate, diagnostics, policy, and receipt APIs |
| [Language Server](docs/LANGUAGE_SERVER.md) | LSP completion, hover, and diagnostics |
| [VS Code support](editors/vscode/README.md) | `.aml` file recognition and syntax highlighting |
| [Capabilities](AML_CAPABILITIES.json) | Machine-readable v1.2 development feature discovery |

## Reproduce and challenge it

| Proof resource | Purpose |
|---|---|
| [Independent replication protocol](REPLICATION.md) | Reproduce compiler behavior independently |
| [Conformance manifest](CONFORMANCE.json) | Machine-readable fixture contract |
| [Render Decision Protocol](docs/RENDER_DECISION_PROTOCOL.md) | Decision artifact semantics |
| [Render Decision JSON Schema](schema/render-decision.schema.json) | Validate render decisions |
| [Execution Receipt JSON Schema](schema/execution-receipt.schema.json) | Validate accountable execution receipts |
| [Build integrity](docs/BUILD_INTEGRITY.md) | Verify hashes and reproducible builds |
| [Benchmarking protocol](docs/BENCHMARKING.md) | Measure compiler throughput without overstating results |
| [Semantic diagnostics](docs/DIAGNOSTICS.md) | Understand semantic completeness checks |
| [Testing](TESTING.md) | Verification philosophy and automated coverage |

## Editor + tooling stack

ĀML already includes:

- `.aml` VS Code language definition
- syntax highlighting
- machine-readable language catalog
- completion API
- hover API
- semantic diagnostics
- dependency-free `aml-lsp` stdio language server
- LSP transport smoke tests

## What ĀML proves — and what it does not

ĀML can make policy inputs explicit, run reproducible policy decisions, record runtime context, hash related artifacts, and cryptographically attest to recorded execution receipts.

That **does not prove**:

- that a policy is morally correct;
- that declared attention/restoration values are empirically valid;
- that AI-generated intent is truthful or aligned with a user's interests;
- that a signed system is trustworthy simply because it owns a private key.

The contribution is architectural: assumptions and decisions that are usually implicit can become inspectable, testable, replaceable, and attestable.

## The research question is getting bigger

The original question was:

> What changes when an interface must explain the attention it consumes?

The v1.2 question is:

> What changes when an AI-generated interface must declare its intent, pass user-owned policies, preserve the decision trail, and produce a verifiable receipt before reaching a human?

## Build with us

Useful contributions include parser tests, policy engines, privacy and accessibility profiles, adversarial policy tests, semantic-diff tooling, policy conflict resolution, signed policy packs, runtime audit streams, AI-generated interface experiments, security review, conformance fixtures, and empirical evaluation methods.

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before submitting work.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**

Code is available under the [MIT License](LICENSE). ĀML™, ĀRU Meaning Language™, EthicalRenderGate™, Meaning-Native Computing™, and ĀRU Intelligence Inc.™ are claimed marks of ĀRU Intelligence Inc.; trademark rights are separate from the code license.
