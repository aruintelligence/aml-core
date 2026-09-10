# Independent ĀML Benchmark Report Template

Use this template when publishing a benchmark or performance reproduction for ĀML. PASS, FAIL, MIXED, regression, and unsupported results are all useful when the methodology is reproducible.

## 1. Report identity

- Report title:
- Report date/time (UTC):
- Reporter / organization:
- Public report URL:
- Public source/harness URL:
- Independence statement:

State clearly whether this is:

- the ĀRU-owned reference implementation run by the project;
- the reference implementation reproduced by an independent party;
- an independently implemented compatible runtime;
- an external pilot or production deployment.

Do not use “independent implementation” for a wrapper around or import of the reference implementation.

## 2. Exact AML target

- Repository: `aruintelligence/aml-core`
- Release/tag:
- Exact commit SHA:
- Contract/specification version tested:
- Compatibility/conformance level, if applicable:

## 3. Implementation

- Implementation name:
- Source URL:
- Language:
- Compiler/runtime and exact version:
- Dependency versions relevant to the measured path:
- Build mode / optimization flags:

## 4. Environment

- Operating system/version:
- Architecture:
- CPU:
- Logical/physical core count:
- RAM:
- Bare metal / VM / container / cloud instance:
- Browser/version, if relevant:
- Power/thermal mode, if relevant:
- Other material environment notes:

## 5. Benchmark class

Choose one primary class from [BENCHMARKING.md](../BENCHMARKING.md):

- B1 compiler throughput
- B2 semantic and policy analysis
- B3 decision and receipt generation
- B4 verification and tamper rejection
- B5 protocol/interoperability
- B6 browser integration
- B7 HTTP/service evaluation
- B8 end-to-end interface decision

If multiple classes are tested, report them separately.

## 6. Fixtures and corpus identity

For every fixture/corpus item record:

- path/name:
- byte size:
- SHA-256:
- expected semantic/decision behavior:
- source of the fixture:

If you modify a published fixture, publish the modified bytes and hash. Do not call a modified fixture identical to the canonical fixture.

## 7. Method

- Warm-up iterations:
- Measured iterations per sample:
- Number of independent samples/runs:
- Concurrency:
- Clock/timing source:
- Setup excluded from timing:
- Setup included in timing:
- Cache state:
- Network assumptions:
- Process restart policy between runs:
- Randomization/order policy:

Explain any deviation from the reference benchmark method.

## 8. Correctness gate

Before interpreting performance, record correctness status.

- Relevant conformance fixtures run: YES / NO
- Conformance result: PASS / FAIL / MIXED / NOT CHECKED
- Canonical/golden vectors run: YES / NO / NOT APPLICABLE
- Vector result: PASS / FAIL / MIXED / NOT CHECKED
- Expected ALLOW/SUPPRESS decisions checked: YES / NO / NOT APPLICABLE
- Receipt/hash/signature checks performed: YES / NO / NOT APPLICABLE
- Deliberate mutation/tamper tests performed: YES / NO / NOT APPLICABLE
- Negative-test result: PASS / FAIL / MIXED / NOT CHECKED

If correctness fails, keep the timing data but label the benchmark result accordingly. Faster incorrect output is not a performance victory.

## 9. Results

For each fixture/operation report, where practical:

- status: PASS / FAIL / MIXED / UNSUPPORTED
- raw samples:
- median latency:
- p95 latency:
- average latency:
- minimum:
- maximum:
- operations/compiles per second:
- failures/timeouts:
- memory data, if measured:

Attach or link the machine-readable report conforming to [`benchmark-report.schema.json`](../benchmark-report.schema.json).

## 10. Comparison, if any

If comparing two implementations/releases:

- exact A target:
- exact B target:
- same fixture bytes? YES / NO
- same operation boundary? YES / NO
- same correctness expectation? YES / NO
- same hardware/environment? YES / NO
- same warm-up/sampling method? YES / NO
- material differences:

If important variables differ, describe the result as a cross-environment or exploratory comparison rather than a direct ranking.

## 11. Reproduction command

```bash
# exact commands used
```

Include setup commands needed to reproduce the environment when practical.

## 12. Interpretation

What does the result directly support?

What does it *not* support?

Potential confounders:

Known limitations:

## 13. Evidence classification

Requested evidence level under [EVIDENCE.md](../EVIDENCE.md): E0 / E1 / E2 / E3 / E4 / E5 / E6 / E7

Why this level is justified:

What additional evidence would be needed for the next level:

## 14. Claim boundary

This report does not, merely by containing benchmark results, establish:

- standards-body approval;
- certification;
- regulatory compliance;
- official ĀRU authorization;
- scientific validation of human-impact inputs;
- improved human outcomes;
- market adoption;
- general superiority over unrelated technologies.

## 15. Reproducibility verdict

- PASS — another party has enough information to attempt reproduction
- MIXED — material information is missing or ambiguous
- FAIL — the result cannot presently be reproduced from the supplied record

Verdict:

Missing information / ambiguity:

---

**Benchmarking is useful when it makes disagreement testable. Publish enough evidence for someone else to reproduce the result, find the flaw, or improve the implementation.**
