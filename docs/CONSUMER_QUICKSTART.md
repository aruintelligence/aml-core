# ĀML consumer quickstart

This page is written for an engineer consuming the package rather than developing the repository.

> Registry status boundary: do **not** assume `npm install aml-core` is available until issue #59 records a verified public npm publication. Until then, use the repository or the audited package artifacts produced by GitHub Actions.

## 1. Verify the package/runtime first

From a package that includes the doctor surface:

```bash
aml-doctor
```

or from a repository checkout:

```bash
npm run doctor
```

A healthy report uses protocol `aml-doctor-report/1` and checks the Node runtime, package entrypoint, CLI entrypoint, and a deterministic parse/compile/governance path.

The doctor proves local package/runtime health only. It is not certification, standards status, independent validation, or a production-suitability claim.

## 2. Run one inspectable AML decision

```bash
aml validate examples/simple.aml
aml inspect examples/simple.aml
```

The first command exercises parsing/evaluation. The second exposes the Abstract Meaning Tree and render decisions rather than hiding them behind rendered output.

## 3. Reproduce the public proof

From the canonical repository:

```bash
npm run proof
npm run proof:report
```

The first command runs the deterministic proof and ALLOW/SUPPRESS fixtures. The second emits a machine-readable report suitable for attaching to a verification result.

## 4. Use the JavaScript API

```js
import { compileSource, runAmlDoctor } from "aml-core";

const health = runAmlDoctor();
if (!health.healthy) throw new Error("AML package health check failed");

const source = `transmission "hello" {
  engram card {
    value: "Hello from AML"
    purpose: "demonstrate accountable rendering"
    memory_role: "demo"
    user_effect: "clarity"
    attention_cost: 1
    restoration_value: 2
  }
}`;

const compiled = compileSource(source, {
  timestamp: "1970-01-01T00:00:00.000Z"
});

console.log(compiled.renderDecisions);
```

## 5. Know which release channel you are evaluating

`v1.3.0` is the stable package/CLI/capability contract. `v1.4.0-rc.2` is the current GitHub prerelease snapshot of the broader architecture on `main`.

Do not describe project-authored tests, package doctor output, repository CI, clone counts, or project-maintained reference implementations as independent adoption or external verification.
