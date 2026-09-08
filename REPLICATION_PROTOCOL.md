# ĀML™ Independent Replication Protocol

ĀML is intended to be challenged through reproducible execution, not accepted on description alone.

## Goal

A replication should determine whether a fresh checkout can:

1. run the automated tests;
2. compile representative `.aml` programs;
3. emit the documented accountability artifacts;
4. preserve declared meaning into machine-readable output;
5. produce reproducible render decisions for the same source and runtime version.

## Procedure

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
node --version
npm test
node bin/aml.js compile examples/simple.aml dist/replication-simple
node bin/aml.js compile examples/ai_assistant_response.aml dist/replication-ai
```

Record:

- operating system
- Node.js version
- Git commit SHA
- test results
- compiler exit status
- emitted artifact names
- any differences or failures

## Required artifacts

For each successful compile, verify the presence of:

```text
index.html
tokens.json
ast.json
amt.json
render_decision.json
```

## Meaning-preservation check

Open the source `.aml` file and compare its declared fields against the emitted AST and Abstract Meaning Tree. Document which fields survive, transform, or disappear.

## Gate check

Inspect `render_decision.json` and compare the policy outcome against the declared or derived inputs used by the current runtime.

## Adversarial replication

A useful replication should also try to break the system:

- malformed syntax
- missing values
- extreme policy inputs
- unexpected strings
- repeated declarations
- large source files
- conflicting semantic intent

Report failures as reproducible test cases whenever possible.

## What replication does not prove

Successful replication demonstrates software behavior. It does not prove that the current attention/restoration model is scientifically validated or ethically universal. Those are separate empirical questions.

## Report results

Repository: https://github.com/aruintelligence/aml-core

Use a GitHub issue or pull request with the exact commit SHA and reproduction steps.

Created by **Daniel Jacob Read IV** and stewarded by **ĀRU Intelligence Inc.™**
