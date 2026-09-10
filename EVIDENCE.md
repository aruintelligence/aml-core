# ĀML Evidence Hierarchy

ĀML™ should become harder to overclaim as it becomes easier to discover.

This document defines a public hierarchy for describing evidence around ĀML — from project-authored demonstrations through independent implementation and real deployment evidence.

The rule is simple:

**Use the strongest label the evidence actually earns, and no stronger.**

## Level E0 — Concept or proposal

Examples:

- design ideas;
- draft architecture;
- proposed use cases;
- research questions;
- future protocol directions.

Allowed language:

- proposed;
- draft;
- exploratory;
- candidate;
- research direction.

Do not describe E0 material as shipped, independently verified, production proven, or adopted.

## Level E1 — Project-authored demonstration

Examples:

- public proof pages;
- demos;
- example receipts;
- reference implementation output;
- project-maintained documentation examples.

E1 establishes that the project can demonstrate a behavior in its own environment.

Allowed language:

- demonstrated by the reference project;
- project-authored proof;
- reproducible in the reference implementation, if reproduction instructions exist.

E1 does not establish independent verification.

## Level E2 — Automated repository verification

Examples:

- CI passing;
- conformance fixtures passing;
- package rehearsal passing;
- release-coherence checks;
- claims guards;
- deterministic replay tests;
- tamper-rejection tests;
- verifier-contract checks.

E2 establishes that automated controls verified defined repository contracts at a specific commit/run.

Allowed language:

- CI-verified;
- repository-verified;
- conformance checks passed;
- automated verification passed.

E2 is still project-controlled evidence.

## Level E3 — Independent reproduction

An external person or organization reproduces a defined result without simply repeating a project-owned screenshot or trusting the original execution environment.

Useful evidence includes:

- exact commit/version;
- external environment;
- reproduction commands;
- expected and observed result;
- receipt/hash/signature evidence;
- PASS, FAIL, or MIXED result;
- public report URL where possible.

Allowed language:

- independently reproduced;
- externally reproduced;
- independently tested.

Do not describe E3 as independent implementation unless the implementation itself is independent.

## Level E4 — Independent implementation

A separate implementation consumes public AML specifications, schemas, fixtures, or protocol vectors without importing or wrapping the reference implementation internals for the behavior under test.

Examples:

- a third-language verifier;
- independent conformance runtime;
- separate semantic-release verifier;
- independent canonicalization/signature implementation.

Allowed language:

- independently implemented;
- cross-runtime reproduction;
- independent implementation passed/failed/mixed against specified vectors.

E4 is strong interoperability evidence for the specific contract tested. It is not standards-body approval or universal compatibility.

## Level E5 — External pilot evidence

A real external team evaluates AML in a bounded workflow such as shadow mode, canary, or a controlled pilot.

A useful pilot record states:

- organization or anonymized context if disclosure is restricted;
- scope;
- AML version;
- deployment mode;
- policy/profile;
- duration/sample size;
- observed outcomes;
- false positives/false negatives where applicable;
- operational overhead;
- failures/limitations;
- whether results were independently reviewed.

Allowed language:

- external pilot;
- evaluated in a bounded external environment;
- shadow/canary pilot evidence.

Do not turn one pilot into a broad adoption claim.

## Level E6 — Production deployment evidence

A real external production environment uses AML for a defined scope and can document the deployment credibly.

Useful evidence includes:

- deployment scope;
- duration;
- version/policy management;
- availability/failure handling;
- security review;
- rollback design;
- evidence/receipt verification;
- operational ownership;
- measurable outcomes and limitations.

Allowed language:

- production deployment for the documented scope;
- deployed in production by/at <scope>, when disclosure is authorized.

E6 still does not imply universal suitability, regulatory approval, or standards adoption.

## Level E7 — Multi-party ecosystem evidence

Multiple independent implementations, deployments, or evaluators produce compatible or comparable results across environments.

This may support stronger statements about interoperability or ecosystem maturity, but only within the tested scope.

Allowed language must name what is actually supported, for example:

- independently implemented across three runtimes;
- reproduced by multiple external evaluators;
- deployed by multiple independent organizations, if publicly documented and authorized.

Do not convert ecosystem evidence into a claim of universal adoption.

## Standards, certification, and regulatory status are separate axes

No evidence level above automatically means:

- ratified global standard;
- certification;
- regulatory approval;
- legal compliance;
- scientific validation;
- official ĀRU authorization;
- endorsement by a standards body;
- broad market adoption.

Those claims require their own evidence.

## Negative evidence counts

FAIL and MIXED results belong in the record.

A credible evidence system must preserve:

- reproducible failures;
- ambiguous specification behavior;
- incompatible independent implementations;
- security findings;
- false positives/false negatives;
- operational regressions;
- withdrawn or superseded evidence.

The goal is not to manufacture consensus. The goal is to make the truth easier to inspect.

## Evidence records should be immutable enough to cite

Where possible, evidence should identify:

- date/time;
- commit or release;
- environment;
- exact input/artifact;
- policy/profile;
- output;
- receipt/hash/signature;
- result classification;
- author/evaluator;
- public source URL;
- supersession/withdrawal status.

## Existing AML evidence surfaces

- [Claims ledger](CLAIMS.md)
- [Public Witness Protocol](publications/AML_WITNESS_PROTOCOL.md)
- [Public Challenge Map](CHALLENGES.md)
- [Verify AML](VERIFY.md)
- [WITNESSES.json](WITNESSES.json)
- [Conformance](conformance/)
- [Adoption path](ADOPTION.md)
- [Security evaluation checklist](docs/SECURITY_EVALUATION_CHECKLIST.md)

## Machine-readable hierarchy

Automated systems can consume [`evidence-levels.json`](evidence-levels.json).

## Report template

Use [Evidence Report Template](docs/EVIDENCE_REPORT_TEMPLATE.md) for reproducible external or internal reports.

## Evidence boundary

This hierarchy is a project governance mechanism. It does not create a certification program, standards-body status, regulatory approval, scientific validity, or official trademark authorization.

**AML should never need inflated language if the evidence is strong enough to stand on its own.**
