# A Critic's Guide to ĀML

**Status: SHIPPED**

ĀML should be easy to criticize precisely.

## Strong criticisms to test

### 1. The scores are subjective
Correct concern. The current prototype treats attention cost and restoration value as declared/model inputs, not objective measurements.

Test: can the project remain useful even when the scoring model is contested?

### 2. An AI can lie about purpose
Correct concern. A receipt can preserve a declaration; it cannot prove the declaration was truthful.

Test: what external evidence or policy should constrain declarations?

### 3. A policy can be bad
Correct concern. Cryptographic integrity does not make a policy wise.

Test: can policy dissent and alternative profiles remain inspectable?

### 4. The interface layer may be too intrusive
Test the HTML bridge or `<aml-gate>` and measure integration cost rather than assuming it.

### 5. Reference implementations can share the same bug
Correct concern. That is why the project publishes a black-box verifier contract and asks for outside implementations.

### 6. AML could become terminology-heavy
Correct concern. The public product story should stay narrow: interface firewall, attention cost, restoration value, receipt, View Meaning, Meaning Gate.

## Best way to attack the project

Reproduce a public artifact independently, find a mismatch, and publish the smallest failing case.

Verify path:
https://github.com/aruintelligence/aml-core/blob/main/VERIFY.md

Adversarial issue:
https://github.com/aruintelligence/aml-core/issues/19
