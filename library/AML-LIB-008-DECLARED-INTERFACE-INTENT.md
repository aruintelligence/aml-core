# AML-LIB-008 — The Case for Declared Interface Intent

**Status: SHIPPED**

Generated interfaces usually expose the result but not the reason.

ĀML experiments with making interface intent explicit enough to evaluate. A message can declare a purpose; a runtime can attach policy-relevant values; a policy can decide whether the output should render; and a receipt can preserve the execution evidence.

Declared intent is not trusted truth. A model or application can misstate its purpose. But undeclared intent is even harder to review because there is nothing explicit to compare with behavior, policy, or later evidence.

The useful question is therefore not:

> Can declaration prove motive?

It cannot.

The useful question is:

> Does requiring a declaration create a better audit boundary than silently rendering generated output?

ĀML is a public prototype for testing that question.

Proof:
https://aruintelligence.github.io/aml-core/proof.html
