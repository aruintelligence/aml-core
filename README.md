# ĀML™ — ĀRU Meaning Language™

## HTML asks whether it *can* render. ĀML asks whether it *should* — then records the meaning, policy, runtime context, attention cost, output, and proof trail.

[![CI](https://github.com/aruintelligence/aml-core/actions/workflows/ci.yml/badge.svg)](https://github.com/aruintelligence/aml-core/actions/workflows/ci.yml)
[![Playground](https://img.shields.io/badge/OPEN-AML_PLAYGROUND-7df9ff?style=for-the-badge&labelColor=07111f)](https://aruintelligence.github.io/aml-core/playground.html)
[![Live Lab](https://img.shields.io/badge/OPEN-LIVE_LAB-a994ff?style=for-the-badge&labelColor=07111f)](https://aruintelligence.github.io/aml-core/)
[![Release](https://img.shields.io/badge/AML-v1.3.0-f2ce72?style=for-the-badge&labelColor=07111f)](https://github.com/aruintelligence/aml-core/releases/tag/v1.3.0)
[![License: MIT](https://img.shields.io/badge/CODE-MIT-9cffb0?style=for-the-badge&labelColor=07111f)](LICENSE)

**ĀML is a working research prototype for meaning-native, policy-aware, accountable AI interfaces.** It sits between machine/human intent and final interface output, preserving inspectable policy decisions and verifiable accountability artifacts.

> AI can propose an interface. ĀML asks what it means, which rules apply, what attention it consumes, whether it should render, and how that decision can be independently checked.

[**Launch the browser playground →**](https://aruintelligence.github.io/aml-core/playground.html)

## ĀML Core v1.3.0

v1.3 adds six major capabilities on top of v1.2 Accountable AI Execution:

1. **Signed policy packs** — data-only policy compositions with canonical hashes and Ed25519 signatures.
2. **Semantic diffs** — compare Abstract Meaning Trees instead of only changed source lines.
3. **Policy diffs** — show exactly which render outcomes change when policy/profile changes.
4. **Runtime audit streams** — append-only SHA-256 hash chains for execution events.
5. **Accessibility policies** — reduced-motion, contrast-safety, and cognitive-load rules driven by runtime context.
6. **Cumulative attention accounting** — session ledgers that track attention consumption across multiple rendered elements.

Read the full [v1.3 breakthrough architecture](docs/V1_3_BREAKTHROUGH.md).

## Current execution architecture

```mermaid
flowchart LR
    A["AI / machine intent"] --> B["Deterministic intent compiler"]
    B --> C["ĀML source"]
    C --> D["AST + Abstract Meaning Tree"]
    D --> E["Policy simulation / policy profile"]
    E --> F["Consent + privacy + accessibility"]
    F --> G["Cumulative attention ledger"]
    G --> H["Final render decisions"]
    H --> I["HTML output"]
    I --> J["Hash-chained runtime audit stream"]
    J --> K["Accountable execution receipt"]
    K --> L["Optional Ed25519 attestation"]
```

## Built-in policy engines

| Policy | Purpose |
|---|---|
| `restorative_v1` | Require restoration value ≥ attention cost |
| `attention_conservative_v1` | Require a 20% restoration margin |
| `consent_guard_v1` | Enforce declared consent requirements |
| `privacy_guard_v1` | Enforce privacy consent for declared personal-data collection |
| `session_attention_budget_v1` | Compare a node with remaining attention budget |
| `reduced_motion_v1` | Respect reduced-motion runtime preference |
| `contrast_safety_v1` | Reject explicitly contrast-unsafe nodes when high contrast is required |
| `cognitive_load_guard_v1` | Enforce a runtime maximum cognitive-load threshold |

## Built-in profiles

| Profile | Focus |
|---|---|
| `calm_default` | restoration + consent |
| `strict_attention` | conservative attention + consent + budget |
| `privacy_first` | restoration + consent + privacy + budget |
| `accessibility_first` | restoration + consent + motion + contrast + cognitive load + budget |
| `human_first` | broad restoration + consent + privacy + accessibility + budget policy stack |

Profiles currently compose with `all_must_allow`: one denying policy is enough to suppress the node.

## Signed policy packs

ĀML v1.3 policy packs are deliberately **data-only**. A pack can reference installed policy IDs but cannot silently transport executable JavaScript.

```bash
node bin/aml.js sign-policy-pack policy-pack.json private-key.pem signed-policy-pack.json
node bin/aml.js verify-policy-pack signed-policy-pack.json
```

## Semantic and policy diffs

```bash
node bin/aml.js semantic-diff before.aml after.aml
node bin/aml.js policy-diff interface.aml calm_default human_first context.json
```

A semantic diff reports structural/property/meaning changes. A policy diff holds source and context constant and reports changed allow/suppress outcomes and rationales.

## Runtime audit streams

Every audit entry commits to its payload and previous entry hash:

```text
entry 0 → hash 0
entry 1 + hash 0 → hash 1
entry 2 + hash 1 → hash 2
```

Mutating a past entry breaks verification.

```bash
node bin/aml.js verify-audit audit-stream.json
```

## Cumulative attention accounting

A session ledger can enforce a shared budget across multiple components:

```text
budget 10
A costs 3 → 7 left
B costs 4 → 3 left
C costs 5 → suppressed by cumulative budget
```

```bash
node bin/aml.js attention-account interface.aml 10 restorative_v1
```

The accountable execution pipeline can bind the ledger and runtime audit stream into the final receipt.

## Accountable AI execution

```bash
node bin/aml.js execute intent.json human_first context.json receipt.json
node bin/aml.js verify-receipt receipt.json
node bin/aml.js sign-receipt receipt.json private-key.pem signed-receipt.json
node bin/aml.js verify-signed-receipt signed-receipt.json
```

A v1.3 receipt can bind:

- original intent
- generated ĀML source
- policy simulations
- selected profile and decisions
- runtime context
- cumulative attention ledger
- runtime audit stream
- final HTML
- SHA-256 integrity values
- optional Ed25519 receipt signature

## CLI

```text
aml compile
aml generate
aml execute
aml verify-receipt
aml sign-receipt
aml verify-signed-receipt
aml simulate
aml semantic-diff
aml policy-diff
aml sign-policy-pack
aml verify-policy-pack
aml verify-audit
aml attention-account
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

## Developer + proof surface

| Resource | Purpose |
|---|---|
| [Browser Playground](https://aruintelligence.github.io/aml-core/playground.html) | Type AML and inspect tokens, AST, AMT, and decisions |
| [Live Lab](https://aruintelligence.github.io/aml-core/) | Operate the baseline EthicalRenderGate™ model |
| [v1.3 breakthrough](docs/V1_3_BREAKTHROUGH.md) | Signed policies, diffs, audit streams, accessibility, attention accounting |
| [Accountable AI Pipeline](docs/ACCOUNTABLE_AI_PIPELINE.md) | Intent → policy → receipt architecture |
| [Quickstart](QUICKSTART.md) | Clone, test, compile, inspect |
| [JavaScript API](API.md) | Public programmatic API |
| [Capabilities](AML_CAPABILITIES.json) | Machine-readable feature discovery |
| [Independent replication](REPLICATION.md) | Reproduce the compiler behavior |
| [Conformance](CONFORMANCE.json) | Public conformance entry point |
| [Canonical fixtures](conformance/manifest.json) | Executable fixture inventory |
| [Testing](TESTING.md) | Verification philosophy |

## Repository quality gates

Every push and pull request checks:

- local Markdown link integrity
- automated unit/integration tests
- CLI compilation
- build-manifest integrity
- in-memory validation
- semantic lint
- explanation output
- inspectable decisions
- benchmark execution

Broken local repository links fail CI rather than silently becoming GitHub 404s.

## Evidence boundary

ĀML improves inspectability, policy control, reproducibility, and cryptographic integrity. It does **not** establish that its policies are universally ethical, that declared attention/restoration scores are validated measurements of human cognition, that an AI's declared intent is truthful, or that current accessibility policies replace WCAG conformance and assistive-technology testing.

Cryptographic signatures prove integrity and control of a signing key; they do not by themselves establish trustworthiness.

## Research question

> What changes when an AI-generated interface must declare meaning, pass user-owned policy, respect cumulative human attention, preserve a runtime audit trail, and produce a verifiable receipt before reaching a person?

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**

Code is available under the [MIT License](LICENSE). ĀML™, ĀRU Meaning Language™, EthicalRenderGate™, Meaning-Native Computing™, and ĀRU Intelligence Inc.™ are claimed marks of ĀRU Intelligence Inc.; trademark rights are separate from the code license.
