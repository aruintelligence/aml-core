# ĀML™ Independent Replication Protocol

This document defines a minimal independent procedure for reproducing the observable behavior of ĀML Core without relying on screenshots or prose claims.

## 1. Clone and identify the version

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
node bin/aml.js version
```

For a published release, check out the corresponding tag before running the remaining steps.

## 2. Install and test

```bash
npm install --ignore-scripts
npm test
```

A replication should record the Node.js version, operating system, ĀML commit/tag, and test result.

## 3. Compile a canonical fixture

```bash
node bin/aml.js compile conformance/allow.aml dist/replication-allow
node bin/aml.js verify dist/replication-allow/build_manifest.json
```

Expected major artifacts:

- `index.html`
- `tokens.json`
- `ast.json`
- `amt.json`
- `render_decision.json`
- `build_manifest.json`

## 4. Exercise both canonical outcomes

```bash
node bin/aml.js inspect conformance/allow.aml
node bin/aml.js inspect conformance/suppress.aml
```

The allow fixture is intended to produce an allowed render decision under the baseline restorative policy. The suppress fixture is intended to produce a suppressed decision.

## 5. Verify deterministic compilation

Use a fixed timestamp when calling `compileSource()` from JavaScript and compare serialized artifacts across repeated runs. Inputs, compiler version, policy, runtime context, and timestamp must be held constant.

## 6. Exercise policy differences

```bash
node bin/aml.js simulate conformance/allow.aml restorative_v1,attention_conservative_v1
```

Record each policy ID and its resulting decisions. Counterfactual simulation is meaningful only when the source and runtime context are identical across policy runs.

## 7. Verify accountable AI execution

Create or use a machine-readable intent object and run:

```bash
node bin/aml.js execute intent.json calm_default context.json receipt.json
node bin/aml.js verify-receipt receipt.json
```

The receipt binds the original intent, generated ĀML source, simulations, selected policy result, final output, and SHA-256 digests.

## 8. Report deviations

A useful replication report includes:

- commit or release tag
- Node.js version
- operating system
- commands run
- fixture(s) used
- observed decision outputs
- verification results
- exact deviation, if any

Do not describe a differing policy judgment as a compiler defect unless the same declared policy, inputs, context, and version were used.

## Evidence boundary

Replication can establish that the implementation behaves reproducibly under specified inputs. It does not establish that a policy is morally correct or that declared attention/restoration values are empirically validated human measurements.
