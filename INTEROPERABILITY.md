# ĀML™ Interoperability

## One contract should survive more than one implementation

ĀML is not credible merely because one codebase can read its own output. The long-term test is whether separately written implementations can consume the same public contracts, reproduce required bytes and decisions, exchange artifacts, reject invalid inputs, and document disagreements without depending on hidden reference internals.

This page is the human-readable map of the current interoperability surface. The machine-readable companion is [`implementation-matrix.json`](implementation-matrix.json).

## Current implementation classes

### JavaScript reference runtime

**Ownership:** ĀRU / project-controlled reference implementation.

The main JavaScript codebase is the reference compiler/runtime and exposes the broad AML implementation surface documented by the repository, including parsing/compilation, Abstract Meaning Tree output, policy/semantic analysis, rendering decisions, receipts, browser integration, service/CLI surfaces, and the broader accountability stack.

This implementation is the reference target. Its existence does not constitute independent replication.

### Python witness verifier

**Ownership:** project-controlled reference interoperability implementation.

Location: [`independent/python/`](independent/python/)

The Python verifier is deliberately separated from the JavaScript verifier internals and uses the Python standard library to reproduce the public `aml-witness-bundle/1` verification contract, including receipt/evidence/bundle hashes, challenge binding/expiry, P-256 public-key validation, JWK fingerprinting, and ECDSA verification.

Because it is maintained inside `aruintelligence/aml-core`, it is **not an independent external witness** and must not be presented as third-party adoption.

### Go witness verifier

**Ownership:** project-controlled reference interoperability implementation.

Location: [`independent/go/`](independent/go/)

The Go verifier uses the Go standard library and separately implements the public `aml-witness-bundle/1` verification path, including canonicalization within the published safe domain, integrity hashes, challenge checks, JWK validation/fingerprinting, and raw P-256 ECDSA verification.

Because it is maintained inside `aruintelligence/aml-core`, it is **not an independent external witness** and must not be presented as third-party adoption.

## Why three project-controlled implementations still matter

They are not external evidence, but they reduce one important class of risk: accidental dependence on one language/runtime or one shared verifier implementation.

Cross-language disagreement becomes visible when JavaScript, Python, and Go independently implement the same public artifact contract. That is stronger engineering evidence than one implementation testing itself, but weaker evidence than an implementation maintained by an unaffiliated party.

Use [`EVIDENCE.md`](EVIDENCE.md) to keep that distinction explicit.

## Compatibility layers

ĀML documentation uses layered compatibility targets so an implementation does not need to implement every experimental feature to participate meaningfully.

The repository currently describes these compatibility levels:

1. **Core** — language/core contract surface.
2. **Accountable** — accountability evidence and policy/decision surfaces.
3. **Federated** — cross-system/federated protocol capabilities.
4. **Verifiable** — verification-oriented artifacts and reproducibility surfaces.
5. **Governed** — governance/authorization-oriented surfaces.

A matrix entry must state the exact contracts tested. A compatibility label is not permission to infer support for every repository feature.

## Current interoperability milestone

The project is presently on the path between **reference implementation / stable public contracts** and **external independent implementation**.

The repository's standardization path intentionally requires independent implementations and later end-to-end interoperability before stronger standardization claims are appropriate.

Open implementation challenges include:

- [Independent AML conformance implementation — issue #1](https://github.com/aruintelligence/aml-core/issues/1)
- [Third-runtime witness challenge — issue #15](https://github.com/aruintelligence/aml-core/issues/15)
- [Independent semantic-release verifier — issue #56](https://github.com/aruintelligence/aml-core/issues/56)
- [General call for independent verification — issue #88](https://github.com/aruintelligence/aml-core/issues/88)

See [`CHALLENGES.md`](CHALLENGES.md) for the full challenge ladder.

## What qualifies as an external independent implementation

For AML project evidence, an implementation should be called **external independent** only when the relevant conditions are documented, including:

- source or sufficiently inspectable implementation is maintained outside `aruintelligence/aml-core`;
- it does not import, execute, or merely wrap the reference implementation for the behavior being claimed as independently implemented;
- the public contract/specification used is identified;
- the target release/commit/contract version is pinned;
- reproducible commands and environment information are published;
- canonical/golden vectors are tested where relevant;
- deliberate invalid/tampered cases are tested where relevant;
- PASS, FAIL, MIXED, and ambiguity results are permitted;
- deviations from the reference behavior are disclosed rather than hidden.

Independence is a property of the evidence relationship, not a branding badge.

## Interoperability proof ladder

### I0 — One implementation, internal tests

A single implementation passes its own tests. Useful engineering baseline, not interoperability.

### I1 — Separate implementation path inside the project

A separately written runtime/verifier within project control reproduces a public contract without importing the reference internals for that behavior.

The in-repo Python and Go witness verifiers are examples of this class for their stated witness-verification contract.

### I2 — External independent reproduction

An unaffiliated party reproduces an exact project artifact/result or verifies a public vector using enough published information to repeat the result.

### I3 — External independent implementation

An externally maintained implementation independently implements a published AML contract and passes relevant canonical/conformance vectors, including negative cases.

### I4 — Cross-implementation artifact exchange

Two implementations exchange and validate real AML artifacts across the same versioned contract rather than merely running isolated fixture tests.

### I5 — Negotiated interoperability

Two independent runtimes negotiate capability/version compatibility, exchange required policy/capability/provenance artifacts, validate receipts, and reject incompatible or replayed inputs as specified.

### I6 — Repeated multi-party interoperability

Multiple independently maintained implementations reproduce the exchange across organizations/environments with published results and documented failures.

These interoperability levels are an engineering evidence ladder. They are **not** standards-body certification levels.

## Required matrix fields

Every implementation entry in `implementation-matrix.json` should identify at least:

- implementation ID/name;
- ownership class;
- independence classification;
- language/runtime;
- public source path or URL;
- supported/tested contract identifiers;
- whether canonical vectors are tested;
- whether deliberate negative/tamper tests are tested;
- repository evidence path;
- evidence level and interoperability level justified by current evidence;
- explicit nonclaims.

Unknown support should be recorded as unknown rather than guessed.

## Adding an implementation

Use [`docs/IMPLEMENTATION_REPORT_TEMPLATE.md`](docs/IMPLEMENTATION_REPORT_TEMPLATE.md) when proposing an implementation or interoperability result for the matrix.

A submission should identify exactly what was implemented and tested. It should not claim whole-language compatibility because one verifier contract passed.

## Standards boundary

ĀML is **not currently an industry or Internet standard**. The standardization path requires, among other things, independent implementations, reproducible interoperability evidence, security maturity, implementation-independent specification text, conformance suites, and governance before stronger claims would be justified.

See [`STANDARDIZATION.md`](STANDARDIZATION.md).

Nothing in this matrix implies endorsement by W3C, WHATWG, IETF, ISO, IEEE, NIST, browser vendors, regulators, accessibility organizations, or any other external body.

## Official identity boundary

Technical interoperability or conformance does not automatically grant official ĀRU authorization, endorsement, partnership, certification, compatibility branding, or trademark rights.

See [`TRADEMARKS.md`](TRADEMARKS.md), [`OFFICIAL_AUTHORIZATIONS.json`](OFFICIAL_AUTHORIZATIONS.json), and [`BRAND_TRUST_ROOTS.json`](BRAND_TRUST_ROOTS.json).

## The target

The long-term target is simple to state and difficult to fake:

> A skeptical engineer should be able to implement AML's public contracts without reading reference internals, exchange artifacts with another implementation, independently verify the result, and publish any disagreement.

That is the interoperability standard this project should earn before claiming more.
