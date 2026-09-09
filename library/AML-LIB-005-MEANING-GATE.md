# AML-LIB-005 — Meaning Gate

**Status: SHIPPED**

Meaning Gate asks a question ordinary CI rarely asks:

> Did the interface meaning change in a way that deserves review?

A code diff can be small while the user-facing effect is large. A generated interface can also change behavior because of model output, policy, or data rather than a large source patch.

Meaning Gate is the CI path for comparing interface meaning and policy-relevant changes before deployment.

Potential review signals include:

- new personal-data collection
- changed consent requirements
- higher attention cost
- lower restoration value
- a new suppression decision
- a high-risk semantic change
- a policy change that alters rendering

Example:

```yaml
- uses: aruintelligence/aml-core/actions/meaning-gate@main
  with:
    before-file: before.aml
    after-file: after.aml
    before-policy: calm_default
    after-policy: human_first
```

Meaning Gate does not prove that a change is harmful. It makes meaning-bearing changes harder to hide inside ordinary code churn.

Repo:
https://github.com/aruintelligence/aml-core
