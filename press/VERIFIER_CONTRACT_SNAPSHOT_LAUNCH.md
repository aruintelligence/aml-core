# The verifier contract now has an immutable address

**PITCH — ready to publish.**

Independent implementations should not have to guess what “AML verifier v1” means.

AML now publishes a contract snapshot that pins the exact verifier rules to an immutable Git commit:

```text
snapshot: aml-verifier-contract-2026-09-08-01
commit: b1ff5a87c7b19ae6338503a58ab6257a5b2add0b
```

That snapshot identifies the exact canonicalization profile, witness schemas, challenge rules, golden vector, CLI contract, conformance-result schema, and black-box harness target.

An implementation can now make a precise claim:

> We implement AML verifier contract snapshot `aml-verifier-contract-2026-09-08-01`.

Then anyone can run the executable against the same four black-box cases:

- golden bundle → PASS
- receipt mutation → FAIL
- challenge mutation → FAIL
- expired challenge → FAIL

Start here:
https://github.com/aruintelligence/aml-core/blob/main/VERIFY.md

Snapshot:
https://github.com/aruintelligence/aml-core/blob/main/protocol/verification-contract-v1.json

This is project-defined compatibility infrastructure, not standards-body certification.

Open the contract. Implement it somewhere else. Run the harness. Publish where you disagree.
