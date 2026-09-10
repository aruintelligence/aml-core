# ĀML™ External Evidence Registry

## External evidence must be earned, not declared

ĀML separates project-controlled evidence from evidence produced outside the control of `aruintelligence/aml-core`.

The canonical machine-readable registry is [`external-evidence.json`](external-evidence.json). It begins empty and must remain empty until qualifying public evidence actually exists.

A record in that registry means only that the cited outside source publicly reported evidence meeting the minimum recorded criteria. It does **not** mean ĀRU endorses the reporter, that the reporter endorses ĀML, that the result is correct beyond its tested scope, or that the result establishes certification, standards status, regulatory compliance, market adoption, scientific validation, or official ĀRU authorization.

## What belongs here

The registry is for evidence that is external to project control and fits one of the E3–E7 classes defined in [`EVIDENCE.md`](EVIDENCE.md):

- **E3 — Independent reproduction**
- **E4 — Independent implementation**
- **E5 — External pilot**
- **E6 — Production deployment**
- **E7 — Multi-party ecosystem evidence**

Project-authored examples, project CI, project-owned Python/Go implementations, project-controlled benchmarks, and self-produced demonstrations remain E0–E2 evidence and must not be promoted into this registry merely because they are public.

## Minimum promotion requirements

A candidate record must provide enough information to support the level requested. At minimum, every accepted record must include:

1. a stable public evidence URL outside the canonical `aruintelligence/aml-core` repository;
2. a named evidence class and requested E-level;
3. the exact AML contract/release/commit or other target tested when applicable;
4. a result: `PASS`, `FAIL`, `MIXED`, or `UNSUPPORTED`;
5. an independence/ownership statement;
6. reproducibility information appropriate to the evidence class;
7. an explicit scope boundary describing what the evidence does and does not support;
8. the date the registry entry was reviewed;
9. the source issue/report used for review.

Additional requirements apply by evidence level.

## E3 — Independent reproduction

A qualifying E3 report should let another party identify:

- the exact public AML artifact, vector, benchmark, proof, or behavior reproduced;
- the target version/commit;
- the external environment;
- the reproduction commands or procedure;
- expected and actual results;
- any failures or ambiguity.

Running the project-controlled reference implementation on an independently controlled machine can qualify as independent reproduction of the tested result if the external relationship is real and documented. It does not become an independent implementation merely because the machine is external.

## E4 — Independent implementation

A qualifying E4 report additionally requires an implementation maintained outside `aruintelligence/aml-core` that does not import, execute, or merely wrap the AML reference implementation for the behavior claimed as independently implemented.

It should identify:

- public implementation source;
- implementation commit/version;
- language/runtime;
- public AML contracts implemented;
- canonical/conformance vectors tested;
- deliberate invalid/tamper cases where relevant;
- deviations or ambiguities;
- exact reproduction instructions.

Passing one contract does not imply whole-language compatibility.

## E5 — External pilot

A qualifying E5 record must describe a real external evaluation or pilot rather than a hypothetical casebook. It should identify, to the extent publicly disclosable:

- the externally controlled environment or organization;
- AML scope used;
- integration boundary;
- evaluation period or event;
- measurable technical result;
- failures, limitations, or rollback information;
- whether the deployment was shadow, canary, advisory, or enforcing.

An external pilot is not production adoption unless production evidence exists.

## E6 — Production deployment

A qualifying E6 record requires public evidence of actual production use for the stated scope. It should identify:

- production system/context sufficiently to verify the claim;
- exact AML capability or contract deployed;
- deployment timeframe;
- operational evidence;
- relevant reliability/security/rollback boundaries;
- who controls the production environment;
- what remains outside the tested/deployed scope.

A production deployment in one system does not imply broad market adoption.

## E7 — Multi-party ecosystem evidence

E7 requires multiple externally controlled parties or independently maintained implementations producing repeatable evidence across organizations/environments. One organization with multiple machines is not automatically multi-party ecosystem evidence.

Useful E7 evidence can include:

- repeated cross-implementation interoperability;
- multiple independent production deployments;
- multi-party artifact exchange/verification;
- reproducible external conformance across separately maintained runtimes.

E7 still does not equal standards-body ratification or certification.

## Negative evidence stays visible

The registry accepts `FAIL`, `MIXED`, and `UNSUPPORTED` records.

A failed independent reproduction can be more informative than a successful internal demo. A protocol ambiguity found by an independent implementation should remain visible until the specification changes or the disagreement is resolved.

Records must not be deleted merely because they are unfavorable. Superseded or resolved results should be retained or linked through an explicit status/history mechanism when practical.

## Promotion process

1. External evidence is submitted through an appropriate issue form or stable public report.
2. The report is checked for ownership/independence, reproducibility, exact target, result, and scope.
3. The requested E-level is reviewed against [`EVIDENCE.md`](EVIDENCE.md).
4. For implementation/interoperability evidence, the requested I-level is also reviewed against [`INTEROPERABILITY.md`](INTEROPERABILITY.md).
5. If accepted, a PR adds the record to `external-evidence.json`.
6. CI validates registry structure, count consistency, external-source constraints, allowed levels, result vocabulary, and required fields.
7. A later correction or downgrade uses another visible PR; evidence classifications are not permanent if the underlying evidence changes.

## Source intake

Relevant structured submission paths include:

- [Independent AML benchmark report](.github/ISSUE_TEMPLATE/independent-benchmark-report.yml)
- [AML implementation / interoperability report](.github/ISSUE_TEMPLATE/implementation-interoperability-report.yml)
- [Independent verification report](.github/ISSUE_TEMPLATE/aml-independent-verification.md)
- [External verifier report](.github/ISSUE_TEMPLATE/external-verifier-report.yml)
- [Independent replication](.github/ISSUE_TEMPLATE/independent-replication.yml)
- [Witness reproduction](.github/ISSUE_TEMPLATE/witness-reproduction.yml)

Use [`docs/EVIDENCE_REPORT_TEMPLATE.md`](docs/EVIDENCE_REPORT_TEMPLATE.md), [`docs/INDEPENDENT_BENCHMARK_REPORT_TEMPLATE.md`](docs/INDEPENDENT_BENCHMARK_REPORT_TEMPLATE.md), or [`docs/IMPLEMENTATION_REPORT_TEMPLATE.md`](docs/IMPLEMENTATION_REPORT_TEMPLATE.md) when a full report is more appropriate than an issue form.

## Relationship to WITNESSES.json

[`WITNESSES.json`](WITNESSES.json) remains the specialized public registry for external verifier/witness reproduction evidence under its own contract.

`external-evidence.json` is broader. A qualifying witness may be represented in both registries when the record satisfies both purposes, but one registry must not be used to inflate the meaning of the other.

## Claim boundary

A registry entry is a citation to evidence, not a certificate.

It does not automatically establish:

- correctness outside the tested scope;
- security or safety certification;
- legal or regulatory compliance;
- standards-body approval or ratification;
- scientific validation;
- market adoption;
- official ĀRU endorsement of the reporter;
- reporter endorsement of ĀRU or ĀML;
- official ĀRU branding/trademark authorization.

**The registry exists so AML can become more credible as outside evidence grows without ever pretending that project-controlled evidence came from somewhere else.**
