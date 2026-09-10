# ĀML Public Witness Protocol

ĀML is stronger when outside people can test it without asking ĀRU for permission.

This protocol gives developers, researchers, security engineers, journalists, standards participants, and skeptics a simple way to create public evidence about what ĀML actually does.

## The rule

**Do not endorse ĀML first. Verify it first.**

A useful witness report should contain enough information for another person to reproduce the result.

## Minimum witness test

1. Open the public proof:
   https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en
2. Record the initial render decision.
3. Change `restoration_value` from `1` to `5`.
4. Record the new render decision.
5. Inspect the receipt/evidence surface.
6. Run the local reproduction path in `demos/undeniable-proof/` or follow `docs/TRY_AML_10_MINUTES.md`.
7. Compare the local result to the public proof.
8. Report both agreement and disagreement.

## Stronger witness test

A stronger report can also:

- inspect a semantic diff
- test a policy change
- test an accessibility or consent condition
- verify a receipt independently
- test a Meaning Gate™ workflow
- evaluate a browser bridge
- test the HTTP contract
- run conformance fixtures
- examine a claim in `CLAIMS.md` against repository evidence
- attempt to construct a case that should be ALLOW but is SUPPRESS, or the reverse

## What to publish

A high-quality public witness report should include:

- date and UTC offset
- repository commit or release tested
- operating system/runtime where relevant
- exact input or proof URL
- expected result
- actual result
- receipt, hash, or evidence identifier where available
- whether the result was reproducible
- whether the claim being tested is SHIPPED, SPEC, DRAFT, or PITCH
- any failure, ambiguity, security concern, false positive, false negative, or documentation gap

## What not to claim

A successful test does not prove that ĀML is:

- a global standard
- universally adopted
- scientifically validated for human cognition or wellbeing
- secure against every threat
- suitable for every production environment
- officially endorsed by a third party

It proves only what the test actually demonstrates.

## How to challenge ĀML usefully

The most valuable criticism is reproducible criticism.

Instead of:

> “This will never work.”

Prefer:

> “At commit X, with input Y and policy Z, I expected A but got B. Here is the receipt and reproduction.”

That gives maintainers, researchers, and other implementers something concrete to inspect.

## Public evidence over private praise

If you test ĀML and it works, a public reproducible report is more valuable than a private compliment.

If you test ĀML and it fails, a public reproducible failure is more valuable than silent rejection.

Both outcomes improve the project.

## Suggested report title

`[WITNESS] ĀML verification report — <short description>`

A GitHub issue template is provided for this purpose under `.github/ISSUE_TEMPLATE/aml-independent-verification.md`.

## The invitation

**Try it. Break it. Verify it. Publish the result.**

ĀML should earn trust through evidence, not volume.
