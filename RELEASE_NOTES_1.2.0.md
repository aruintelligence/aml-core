# ĀML Core v1.2.0 — Accountable AI Execution

ĀML v1.2.0 moves the project beyond an accountable compiler into an experimental **accountable execution layer between machine-generated intent and human-facing interfaces**.

## Headline architecture

```text
AI / machine intent
  ↓
deterministic intent compiler
  ↓
ĀML source
  ↓
Abstract Meaning Tree
  ↓
counterfactual policy simulation
  ↓
user / organization policy profile
  ↓
composed render decision
  ↓
browser-compatible output
  ↓
SHA-256 execution receipt
  ↓
optional Ed25519 signature
```

## New in v1.2.0

### Accountable execution receipts

- `executeAccountableIntent()`
- `verifyExecutionReceipt()`
- intent SHA-256
- generated AML SHA-256
- policy simulation SHA-256
- render-decision SHA-256
- final-output SHA-256
- receipt SHA-256
- machine-readable execution-receipt JSON Schema

### Signed execution receipts

- `signExecutionReceipt()`
- `verifySignedExecutionReceipt()`
- Ed25519 signatures
- embedded public-key fingerprints
- automated mutation detection

### Policy engine system

Built-in engines now include:

- `restorative_v1`
- `attention_conservative_v1`
- `consent_guard_v1`
- `privacy_guard_v1`
- `session_attention_budget_v1`

### User / organization policy profiles

- `calm_default`
- `strict_attention`
- `privacy_first`

Profiles compose multiple policies under an `all_must_allow` strategy.

### Runtime context

Policies can now consider runtime context such as:

```json
{
  "consent_granted": true,
  "privacy_consent": false,
  "attention_budget_remaining": 5
}
```

The active context is recorded in the execution receipt.

### Counterfactual simulation

The same AML source can be evaluated across multiple policy regimes before a selected composed policy produces the final render decision.

This makes policy differences inspectable rather than burying them in application code.

### Machine intent → AML

v1.2 adds deterministic generation of AML source from constrained machine-readable intent objects. Generated source then passes through the normal parser, meaning-tree, policy, render, and accountability pipeline.

### CLI

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

## Verify

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install
npm test
node bin/aml.js policies
node bin/aml.js profiles
```

Browser playground:

https://aruintelligence.github.io/aml-core/playground.html

Live lab:

https://aruintelligence.github.io/aml-core/

## Evidence boundary

ĀML v1.2 can bind declared intent, policy context, policy decisions, output, hashes, and signatures into inspectable records. It does **not** prove that a policy is morally correct, that declared attention/restoration scores are empirically valid, that an AI-generated intent is truthful, or that a signer is trustworthy merely because it controls a private key.

The contribution is an executable architecture for making those assumptions and decisions explicit, reproducible, testable, replaceable, and attestable.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**

Code is MIT licensed. ĀML™, ĀRU Meaning Language™, EthicalRenderGate™, Meaning-Native Computing™, and related claimed marks remain separate from the code license.
