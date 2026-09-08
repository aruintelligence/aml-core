# Brief for Researchers and Standards Engineers

**Status: SHIPPED**

ĀML is a research prototype exploring whether interface intent can become an interoperable, inspectable layer rather than remaining implicit in rendered output.

The project now exposes:

- public fixtures
- deterministic replay
- JSON Schemas
- canonicalization rules
- immutable verifier contract snapshots
- Python and Go reference verifiers
- black-box conformance harnesses
- explicit migration/lineage rules
- an empty external witness registry that cannot count AML-owned evidence

The most useful criticism is not whether the idea sounds ambitious. It is whether two independent implementations produce the same result from the same artifact.

Verify without trusting the reference runtime:
https://github.com/aruintelligence/aml-core/blob/main/VERIFY.md

Adversarial review:
https://github.com/aruintelligence/aml-core/issues/19

ĀML is not a ratified standard. The goal is to publish enough exact contracts that independent implementations can prove or disprove compatibility.
