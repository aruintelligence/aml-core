# AML-LIB-007 — Independent Verification

**Status: SHIPPED**

ĀML should be verifiable without trusting the page that generated the interface.

The current prototype publishes a portable witness bundle, a detached verifier, and reference verification implementations in JavaScript/browser tooling, Python, Go, and HTTP. A black-box conformance harness tests the same golden artifact and required failure cases.

The objective is not to claim decentralization. All current reference implementations are maintained by the project, and the external witness registry remains empty until an outside maintainer reproduces the result publicly.

The important design rule is narrower:

> Verification should be possible from public contracts and artifacts rather than private implementation knowledge.

Start here:

https://github.com/aruintelligence/aml-core/blob/main/VERIFY.md

External implementations are invited to disagree. A negative reproduction is useful evidence if it is public and reproducible.
