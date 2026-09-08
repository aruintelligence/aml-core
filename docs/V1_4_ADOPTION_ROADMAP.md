# ĀML v1.4 Adoption Roadmap

v1.4 should prioritize **adoption and interoperability** over simply adding more primitives.

## Release goals

### 1. Distribution
- verify and publish a registry package;
- publish release-pinned browser modules;
- provide React, Next.js, and plain-JS starters;
- document exact upgrade and compatibility policy.

### 2. Conformance
- version the conformance fixture contract;
- publish expected canonical decision outputs;
- define requirements for independent implementations;
- expose an ĀML Compatible badge backed by CI.

### 3. Developer experience
- package the VS Code extension for marketplace distribution;
- strengthen LSP diagnostics and code actions;
- provide starter GitHub Actions workflows;
- add copy-paste examples that run without private infrastructure.

### 4. Mainstream demo
- maintain one flagship AI Interface Firewall demo;
- show before/after source;
- show semantic risk diff;
- show policy diff;
- show the final execution receipt in View Meaning;
- show the same change blocked in CI.

### 5. Security and trust
- adversarial fixture suite;
- replay protection research;
- canonicalization attack tests;
- key-rotation/revocation guidance;
- privacy-preserving receipt minimization.

### 6. Portable user policy
- advance RFC 0004;
- design scoped/selective policy disclosure;
- define precedence between user and organization policies;
- test revocation and expiry across sessions.

## Success criteria

v1.4 should be judged less by source-file count and more by whether an unfamiliar developer can:

1. understand the idea in under two minutes;
2. run a demo with zero installation;
3. add AML to an existing app in under ten minutes;
4. put the Meaning Gate into CI;
5. inspect an execution receipt;
6. reproduce conformance results independently.

## Non-goal

v1.4 should not inflate human-impact claims. Software accountability features should remain clearly separated from empirical claims that require independent human-subject research.