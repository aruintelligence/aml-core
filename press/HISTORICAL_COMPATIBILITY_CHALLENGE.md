# Break AML across time

**Status: PITCH**

AML now has an immutable verifier snapshot and explicit migration machinery.

The next adversarial question is not only:

> Can you verify today's artifact?

It is:

> Can a future AML implementation prove exactly what an old artifact meant without silently applying newer rules?

Current snapshot:

`aml-verifier-contract-2026-09-08-01`

Current migration count:

`0`

Challenge the model:

1. identify a realistic future verifier change;
2. classify it as backward-compatible, conditionally-compatible, or breaking;
3. explain how the old artifact keeps its historical meaning;
4. find any ambiguity where a future implementation could silently reinterpret old bytes;
5. publish the disagreement.

Evolution page:
https://aruintelligence.github.io/aml-core/contract-evolution.html

Repository:
https://github.com/aruintelligence/aml-core

A migration classification is interoperability metadata, not certification or proof of correctness.
