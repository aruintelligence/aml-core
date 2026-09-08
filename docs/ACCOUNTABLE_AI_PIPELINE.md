# Accountable AI Execution Pipeline

ĀML™ v1.2 introduces an end-to-end research pipeline designed to separate **AI proposal** from **render permission**.

```text
machine-readable intent
  ↓
deterministic intent compiler
  ↓
ĀML source
  ↓
multiple counterfactual policy simulations
  ↓
user / organization policy profile
  ↓
composed policy decision
  ↓
selected browser output
  ↓
SHA-256 execution receipt
  ↓
optional Ed25519 receipt attestation
```

## Why this architecture matters

An AI model can propose interface intent without receiving unrestricted authority to decide what reaches the user. The proposed meaning is converted into deterministic ĀML source and processed through the same compiler and policy machinery as human-authored source.

The resulting execution receipt binds together:

- original machine-readable intent
- generated ĀML source
- runtime policy context
- policy profile
- counterfactual policy simulations
- selected composed-policy decision
- final browser output
- SHA-256 hashes for each major stage
- optional Ed25519 signature

## JavaScript API

```js
import {
  executeAccountableIntent,
  verifyExecutionReceipt,
  signExecutionReceipt,
  verifySignedExecutionReceipt
} from "aml-core";

const receipt = executeAccountableIntent(intent, {
  profile: "privacy_first",
  context: {
    consent_granted: true,
    privacy_consent: false,
    attention_budget_remaining: 5
  }
});
```

## CLI

```bash
aml execute intent.json privacy_first context.json receipt.json
aml verify-receipt receipt.json
```

## Counterfactual simulation

Before a composed policy is selected, the pipeline runs the same generated source through every policy listed in the active profile. This records how each policy would treat the same semantic input.

That makes policy differences inspectable instead of silently embedding them in application code.

## Receipt integrity

`receipt_sha256` covers the unsigned execution receipt. A mutation to intent, context, simulations, decisions, AML source, or output causes `verifyExecutionReceipt()` to fail.

The receipt can additionally be signed with Ed25519, providing a detached identity/attestation layer on top of content integrity.

## Evidence boundary

This architecture can prove what inputs, policies, decisions, and output were bound together. It does not prove that a policy is morally correct, that declared values are empirically valid, or that an AI-generated intent accurately represents a user's interests.

Those remain research, governance, and validation questions.
