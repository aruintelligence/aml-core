# ĀML™ Release Discipline

This document defines the minimum publication discipline for a release that is presented as a stable or externally testable ĀML™ software/protocol state.

It is an engineering and evidence contract, not a claim of standards-body approval, certification, scientific validation, regulatory compliance, or universal production suitability.

## Release identity

A release intended for outside reproduction SHOULD identify all of the following:

1. semantic version or prerelease identifier;
2. immutable Git commit SHA;
3. package version;
4. applicable verifier-contract snapshot;
5. applicable conformance/test-vector versions;
6. cryptographic hashes for published release artifacts where practical;
7. stable/preview/experimental status.

A moving `main` branch is useful for development but is not a substitute for an immutable release identity.

## Channels

### Stable

A stable release is the current supported package/API contract. Stable does not mean flawless, certified, scientifically validated, or suitable for every production system.

### Preview / release candidate

A preview may contain broader architecture intended for outside testing. Breaking changes remain possible and MUST be stated plainly.

### Experimental

Research artifacts, field experiments, draft RFCs, prototypes, and exploratory interfaces MUST remain distinguishable from the stable package contract.

## Minimum release evidence

Before calling a release ready for broad outside reproduction, the project SHOULD preserve:

- the exact source commit;
- automated test result(s);
- public conformance result(s) where applicable;
- package/artifact manifest and checksums where available;
- external-verifier kit root and manifest where applicable;
- verifier-contract snapshot and migration lineage;
- known limitations and claim boundaries;
- rollback or previous-stable reference.

Where signed release/provenance artifacts exist, they SHOULD bind the exact artifact bytes and the release identity they represent.

## Independent verification boundary

Project-authored CI proves that project-authored checks passed for a particular state. It does not become independent evidence merely because it runs on GitHub infrastructure.

Independent evidence requires an outside implementation, outside reproducer, or other evidence source that satisfies the relevant independence rules. PASS, FAIL, and MIXED results are all valid evidence states.

## Release candidate checklist

Before advancing a new stable release, verify:

- [ ] package/API version coherence;
- [ ] full automated test suite passes;
- [ ] conformance and interoperability checks pass or known failures are disclosed;
- [ ] security workflows have no unexplained blocking failure;
- [ ] external verifier/witness artifacts build deterministically where applicable;
- [ ] published hashes and manifests correspond to the final commit;
- [ ] documentation links resolve;
- [ ] licensing/trademark notices match the intended distribution model;
- [ ] experimental claims are not presented as independent adoption or validation;
- [ ] release notes state breaking changes, migrations, and known limitations.

## Release receipts

A release receipt SHOULD make it possible to answer, without trusting prose alone:

- Which commit was released?
- Which package version was released?
- Which verifier contract applied?
- Which tests or checks were run?
- Which artifact hashes were published?
- Which signing/trust policy applied?
- What was stable versus experimental?

## No retroactive evidence rewriting

Historical releases, snapshots, receipts, and external witness records should remain append-only wherever practical. If a correction is necessary, preserve the original state and publish a correction or superseding record rather than silently rewriting the historical claim.

## Commercial boundary

Release availability under the repository software license does not itself grant rights to official ĀML™/ĀRU™ branding, certification-style identity, endorsement, OEM/co-branding, managed infrastructure, or separately licensed commercial offerings. See `LICENSING.md`, `TRADEMARKS.md`, and `COMMERCIAL.md`.
