# ĀML Evidence Report Template

Use this template to publish a reproducible AML evaluation, whether the outcome is PASS, FAIL, or MIXED.

## 1. Report identity

- Title:
- Date/time + UTC offset:
- Evaluator/organization:
- Public report URL:
- Evidence level claimed: E0 / E1 / E2 / E3 / E4 / E5 / E6 / E7
- Result: PASS / FAIL / MIXED

## 2. AML target

- Repository: https://github.com/aruintelligence/aml-core
- Release/tag:
- Commit SHA:
- Contract/specification tested:
- Policy/profile/version:

## 3. Environment

- Operating system:
- Runtime/language:
- Runtime version:
- Browser/version if applicable:
- Architecture/container details if relevant:
- External dependencies:

## 4. Test objective

State the exact claim or behavior being evaluated.

Avoid broad statements such as “AML works” or “AML fails.” Prefer a falsifiable statement tied to a specific surface.

## 5. Exact input

Provide or link:

- AML source;
- proof URL;
- artifact/receipt;
- fixture/vector;
- API request;
- policy input;
- any preprocessing required.

## 6. Expected result

Describe the result predicted by the public contract or project claim before running the test.

## 7. Actual result

Describe the observed result.

Include where available:

- decision;
- receipt identifier;
- hashes;
- signature result;
- error output;
- semantic/policy diff;
- latency/performance measurements;
- screenshots only as supplemental evidence, not as a substitute for reproducible data.

## 8. Reproduction commands

Provide exact commands or steps another evaluator can run.

```text
<commands here>
```

## 9. Independence statement

State which applies:

- project-authored test;
- repository CI only;
- independently reproduced using reference implementation;
- independently implemented without importing reference internals;
- external pilot;
- production deployment;
- multi-party evidence.

Describe any relationship to ĀRU Intelligence Inc. or the aml-core maintainers that could affect independence classification.

## 10. Tamper / negative test

Where meaningful, mutate one relevant input and show that the result changes or verification fails as expected.

Record both the mutation and observed behavior.

## 11. Failure and ambiguity log

List:

- failures;
- ambiguous specification language;
- unexpected behavior;
- false positives;
- false negatives;
- interoperability mismatches;
- security concerns;
- documentation gaps.

Do not omit negative results to make the report look stronger.

## 12. Scope boundary

State explicitly what this report does **not** establish.

Examples:

- not proof of universal AML correctness;
- not certification;
- not standards-body approval;
- not regulatory compliance;
- not scientific validation of human-impact scores;
- not proof of production security outside the tested scope;
- not official ĀRU trademark authorization.

## 13. Evidence classification rationale

Explain why the report earns the selected E-level under [EVIDENCE.md](../EVIDENCE.md).

## 14. Reproduction status

- Reproduced by a second person/team? yes/no
- Independent implementation? yes/no
- Public source available? yes/no
- Artifacts retained? yes/no
- Superseded/withdrawn? yes/no

## 15. Final statement

Use narrow language tied to the evidence.

Good:

> “At commit X, in environment Y, test Z produced the expected deterministic receipt and the independently implemented verifier accepted it.”

Avoid:

> “AML is proven.”

## Suggested citation line

`ĀML evidence report — <title> — <date> — <commit> — <result> — <public URL>`

**The report is strongest when another person can reproduce both the success and the failure conditions without trusting the author.**
