# Contributing to ĀML™

Thank you for your interest in ĀML™ — ĀRU Meaning Language™.

ĀML is a working research prototype exploring meaning-native interfaces, accountable rendering, policy-aware execution, verifiable receipts, and cross-system interoperability. Please read this guide, the [Code of Conduct](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md) before contributing.

## Project status

The project is under active development. Interfaces, schemas, RFCs, conformance requirements, and policies may evolve. `v1.3.0` remains the stable package/CLI/capability contract; later work on this branch may include breaking authorization semantics. See [CHANGELOG.md](CHANGELOG.md).

## Development setup

1. Install [Node.js](https://nodejs.org/) 20 or 24 (see `.nvmrc`). Python 3 and Go are required for the independent verifier checks that CI runs.
2. Clone the repository and install package metadata without running package lifecycle scripts:

   ```bash
   git clone https://github.com/aruintelligence/aml-core.git
   cd aml-core
   npm install --ignore-scripts
   npm test
   ```

3. Useful local checks, also used in CI:

   ```bash
   npm run check:links
   node scripts/check-project-contract.mjs
   node scripts/check-workflow-safety.mjs
   ```

Keep changes focused. Do not commit secrets, private keys, or unreleased credential material. Do not add production signing material to the repository.

## Contribution areas

Contributions are welcome in areas including:

- compiler and parser development;
- runtime and policy systems;
- interoperability and protocol work;
- conformance tests and independent implementations;
- security and adversarial review;
- accessibility review;
- framework integrations;
- documentation, RFCs, examples, and benchmarks.

## Contribution principles

Contributions should prioritize:

- clarity;
- transparency;
- reproducibility;
- accountability;
- interoperability;
- inspectability;
- maintainability;
- human-centered design.

## Pull request guidelines

Please:

1. keep pull requests focused;
2. document architectural or protocol changes;
3. include rationale for major additions;
4. include tests when behavior changes;
5. call out compatibility and security implications;
6. avoid unsupported scientific, ethical, legal, or compliance claims;
7. follow the [pull request template](.github/pull_request_template.md);
8. be respectful and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Maintainers may ask for changes so public claims, versioning, and authorization exit semantics stay consistent with the project contracts.

## Contribution licensing

By intentionally submitting a contribution to this repository, you represent that you have the right to submit it and agree that your contribution may be distributed under the repository’s MIT License unless a different written agreement is explicitly accepted for that contribution.

Contributors retain whatever copyright they legally own in their original contributions. Submitting code or documentation does **not** transfer ownership of ĀML™, ĀRU Meaning Language™, ĀRU Intelligence Inc.™, official project logos, compatibility branding, certification-style marks, or other project trademarks/service marks.

The project’s brand-use rules are separate from the software license. See `TRADEMARKS.md`.

### No silent relicensing assumption

Submission under the MIT contribution terms above should not be interpreted as a separate copyright assignment to ĀRU Intelligence Inc. or Daniel Jacob Read IV, nor as a blanket agreement allowing the project to relicense a contributor's original work under arbitrary future proprietary terms beyond rights actually granted.

If ĀRU later wants to incorporate an outside contribution into a separately licensed commercial component, dual-licensed product, or other offering that requires rights beyond the applicable MIT grant, the project should obtain any additional contributor permission or agreement that is legally necessary before relying on that contribution for such a purpose.

This protects both the project and contributors from ambiguity about future commercial rights.

### Future contributor agreements

The project may adopt a separate contributor license agreement, developer certificate of origin process, or other written contribution framework for future contributions if broader relicensing, patent, provenance, or commercial-distribution rights become necessary.

Such a framework should be prospective and explicit. This file does not pretend that a future policy can retroactively manufacture rights that were never granted.

## Standards and conformance contributions

Technical participation in the RFC, registry, protocol, conformance, or test process does not by itself grant:

- ownership of the official AML standard identity;
- permission to imply official certification or endorsement;
- a commercial trademark license;
- control of the official project roadmap or registries.

Independent implementations and critical review are encouraged. Factual compatibility claims should remain reproducible and non-misleading.

## Security reports

Do not publish secrets, private keys, exploit details that would create immediate harm, or confidential customer information in public issues. Follow `SECURITY.md` for security reporting guidance.

## Experimental nature

Some AML concepts remain exploratory. Software-level integrity properties can be tested directly; claims about human attention, wellbeing, ethics, accessibility outcomes, or regulatory compliance require evidence beyond the software itself.

## Core principle

```aml
render_allowed = restoration_value >= attention_cost
```

That equation is a declared prototype policy model, not a scientifically validated universal measure of human cognition or wellbeing.
