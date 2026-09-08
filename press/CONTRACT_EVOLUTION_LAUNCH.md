# AML can evolve without rewriting its past

**Status: PITCH**

Most protocol drift starts quietly.

One runtime changes canonicalization. Another changes expiry semantics. Both still say they implement the same version.

AML now publishes an immutable verifier contract snapshot plus explicit migration machinery.

Current snapshot:

`aml-verifier-contract-2026-09-08-01`

The rule is simple:

```text
Snapshot N is immutable.
Snapshot N+1 must declare what changed.
Old artifacts keep Snapshot N meaning.
```

Future verifier-contract changes must publish:

- a new snapshot ID;
- an exact source commit;
- changed locked paths;
- compatibility classification;
- before/after behavior;
- historical-artifact policy.

There is currently one snapshot and zero migration edges. That is intentional. AML will not publish a fake Snapshot 2 just to look active.

Inspect the live evolution page:
https://aruintelligence.github.io/aml-core/contract-evolution.html

Try to break the migration model. Find a case where an old artifact could be silently reinterpreted and file it.

Repository:
https://github.com/aruintelligence/aml-core

Compatibility metadata is project-defined interoperability evidence, not standards-body certification.
