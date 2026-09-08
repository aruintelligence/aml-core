# Historical verification

**Status: SHIPPED prototype contract rule.**

AML evidence must remain interpretable against the verifier contract snapshot that originally defined its bytes and rules.

## Historical invariant

```text
artifact A
+ snapshot S
+ verifier implementing S
= the historical verification result for A under S
```

A future snapshot may be more strict, more permissive, or structurally different. That does not change the historical result under S.

## What a future implementation may do

A future implementation may:

- continue supporting S;
- invoke an S-specific compatibility module;
- report S as unsupported;
- require an explicit migration before processing under a newer snapshot.

It may not silently apply newer semantics and report that as though S itself had changed.

## What migration proves

A migration object records declared compatibility between two snapshot targets. It does not rewrite old artifacts and does not certify the correctness of either snapshot.

## Current historical target

`aml-verifier-contract-2026-09-08-01`

Source commit:

`b1ff5a87c7b19ae6338503a58ab6257a5b2add0b`
