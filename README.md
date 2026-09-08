# ĀML™ — ĀRU Meaning Language™

## The accountability layer between AI and the human interface.

[![CI](https://github.com/aruintelligence/aml-core/actions/workflows/ci.yml/badge.svg)](https://github.com/aruintelligence/aml-core/actions/workflows/ci.yml)
[![Playground](https://img.shields.io/badge/OPEN-AML_PLAYGROUND-7df9ff?style=for-the-badge&labelColor=07111f)](https://aruintelligence.github.io/aml-core/playground.html)
[![View Meaning](https://img.shields.io/badge/OPEN-VIEW_MEANING-9cffb0?style=for-the-badge&labelColor=07111f)](https://aruintelligence.github.io/aml-core/view-meaning.html)
[![Release](https://img.shields.io/badge/AML-v1.3.0-f2ce72?style=for-the-badge&labelColor=07111f)](https://github.com/aruintelligence/aml-core/releases/tag/v1.3.0)
[![License: MIT](https://img.shields.io/badge/CODE-MIT-a994ff?style=for-the-badge&labelColor=07111f)](LICENSE)

**AI can propose an interface. ĀML decides what it means, which policies apply, whether it should render, and what proof trail must exist afterward.**

> **HTML tells the browser what to display. ĀML tells the system why it deserves to be displayed.**

ĀML is a working research prototype for meaning-native, policy-aware, accountable AI interfaces. It does **not** require replacing HTML or React. It can sit in front of existing UI as an **AI Interface Firewall**.

## Start in 60 seconds

- **Try AML:** https://aruintelligence.github.io/aml-core/playground.html
- **Inspect a receipt:** https://aruintelligence.github.io/aml-core/view-meaning.html
- **Read the AI Interface Firewall guide:** [docs/AI_INTERFACE_FIREWALL.md](docs/AI_INTERFACE_FIREWALL.md)
- **See all capabilities:** [AML_CAPABILITIES.json](AML_CAPABILITIES.json)

## AI Interface Firewall

```js
import { createInterfaceFirewall } from "aml-core";

const firewall = createInterfaceFirewall({ profile: "human_first" });

const result = firewall.enforce({
  transmission: "pricing_assistant",
  nodes: [{
    type: "message",
    identifier: "pricing",
    properties: {
      purpose: "Explain pricing clearly",
      content: "Simple pricing",
      attention_cost: 1,
      restoration_value: 2
    }
  }]
});

if (result.allowed) render(result.html);
```

The result carries policy decisions, accessibility analysis, provenance, attention accounting, runtime audit state, and a verifiable execution receipt.

## React adoption without rewriting the app

```jsx
import React from "react";
import { createAccountableUI } from "aml-core";

const AccountableUI = createAccountableUI(React);

<AccountableUI
  id="pricing"
  purpose="Help the user understand pricing"
  attentionCost={1}
  restorationValue={2}
  policy="human_first"
  fallback={<p>Withheld by policy.</p>}
>
  <ExistingPricingComponent />
</AccountableUI>
```

The adapter converts ordinary component metadata into canonical ĀML intent and sends it through the same accountability pipeline as native `.aml` source.

## View Meaning

The web gave developers **View Source**. ĀML introduces **View Meaning**.

```js
import { viewMeaning } from "aml-core";

const meaning = viewMeaning(result.receipt);
```

A View Meaning report can expose:

- declared purpose
- policy/profile
- attention cost
- restoration value
- allow/suppress outcome
- policy rationale
- receipt integrity
- audit/attention hashes

Browser inspector: https://aruintelligence.github.io/aml-core/view-meaning.html

## Meaning Gate for pull requests

ĀML can stop semantic regressions before deployment.

```yaml
- uses: aruintelligence/aml-core/actions/meaning-gate@main
  with:
    before-file: before.aml
    after-file: after.aml
    before-policy: calm_default
    after-policy: human_first
```

The gate can block:

- high-risk meaning changes
- new personal-data collection
- changed consent requirements
- attention/restoration changes
- policy regressions from ALLOW → SUPPRESS

Direct runner:

```bash
node scripts/meaning-gate.js before.aml after.aml calm_default human_first
```

## What exists today

ĀML v1.3 includes:

- lexer + parser
- AST + Abstract Meaning Tree
- compiler to browser-compatible HTML
- pluggable policy engines
- user/organization policy profiles
- policy consensus with explicit dissent
- semantic diffs + semantic risk scoring
- policy diffs + policy matrices
- AI intent → deterministic ĀML generation
- AI Interface Firewall
- React-compatible adapter
- View Meaning API + browser inspector
- GitHub Meaning Gate action
- consent + privacy policies
- expiring/revocable consent ledger
- accessibility policies + audits
- cumulative attention accounting
- signed policy packs
- runtime SHA-256 audit streams
- signed audit checkpoints
- execution provenance graphs
- Merkle-batched execution receipts
- Ed25519-signed execution receipts
- CLI + JavaScript API
- browser playground
- VS Code language support
- LSP server
- CI + conformance fixtures

## Execution architecture

```mermaid
flowchart LR
    A[AI / app intent] --> B[ĀML Interface Firewall]
    B --> C[Intent → ĀML]
    C --> D[AST + Meaning Tree]
    D --> E[Semantic + accessibility analysis]
    E --> F[Policy matrix / consensus]
    F --> G[Consent + privacy + attention]
    G --> H[Render decision]
    H --> I[HTML / existing UI]
    H --> J[Runtime audit stream]
    J --> K[Execution receipt]
    K --> L[Provenance + signature / Merkle proof]
```

## Built-in profiles

| Profile | Focus |
|---|---|
| `calm_default` | restoration + consent |
| `strict_attention` | conservative attention + consent + budget |
| `privacy_first` | restoration + consent + privacy + budget |
| `accessibility_first` | motion + contrast + cognitive load + budget |
| `human_first` | broad privacy + consent + accessibility + attention controls |

## Developer surface

| Resource | Purpose |
|---|---|
| [AI Interface Firewall](docs/AI_INTERFACE_FIREWALL.md) | Adopt AML inside existing apps |
| [Playground](https://aruintelligence.github.io/aml-core/playground.html) | Type AML and inspect compiler structures |
| [View Meaning](https://aruintelligence.github.io/aml-core/view-meaning.html) | Inspect accountable execution receipts |
| [JavaScript API](API.md) | Programmatic API |
| [Quickstart](QUICKSTART.md) | Clone, test, compile, inspect |
| [Trust Continuity](docs/TRUST_CONTINUITY.md) | Consent history, provenance, policy dissent, Merkle receipts |
| [v1.3 Architecture](docs/V1_3_BREAKTHROUGH.md) | Signed policies, diffs, audit streams, accessibility, attention |
| [Capabilities](AML_CAPABILITIES.json) | Machine-readable platform surface |
| [Conformance](CONFORMANCE.json) | Canonical compatibility entry point |
| [Replication](REPLICATION.md) | Independent reproduction protocol |

## Quality gates

Every push checks local documentation links, automated tests, compiler output, bundle integrity, validation, semantic lint, explanation output, inspectable decisions, and benchmarks.

## Evidence boundary

ĀML improves **inspectability, policy control, reproducibility, and cryptographic integrity**. It does not establish that its present attention/restoration scores objectively measure human cognition or wellbeing; it does not make an AI's declared intent truthful; and its accessibility policies do not replace WCAG conformance or assistive-technology testing.

Cryptographic signatures prove integrity and key possession—not moral correctness or institutional trustworthiness.

## The question

> What changes when AI-generated interfaces must declare meaning, pass user-owned policy, respect consent/privacy/accessibility/attention constraints, and produce a verifiable receipt before reaching a person?

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**

Code is available under the [MIT License](LICENSE). ĀML™, ĀRU Meaning Language™, EthicalRenderGate™, Meaning-Native Computing™, and ĀRU Intelligence Inc.™ are claimed marks of ĀRU Intelligence Inc.; trademark rights are separate from the code license.
