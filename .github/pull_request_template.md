## What changes

Describe the smallest durable change in this PR.

## Why now

What concrete problem or evidence justifies changing ĀML now?

## Ten-axis engineering gate

- [ ] **Architecture:** responsibilities stay in the correct layer; no duplicate primitive or hidden coupling.
- [ ] **Contract/compatibility:** public and machine-readable contracts touched are identified; versioning and downgrade behavior are explicit.
- [ ] **Security/abuse:** malformed, adversarial, stale, replayed, conflicting, oversized, and partial inputs were considered where relevant.
- [ ] **Determinism/reproducibility:** ordering, serialization, time, randomness, locale, Unicode, floating point, and pinned evidence are explicit where relevant.
- [ ] **Evidence/claims:** every new SHIPPED claim has evidence and does not imply adoption, certification, standards status, safety, ethics, or compliance beyond what is proved.
- [ ] **Interoperability:** terminology and protocol names were checked for standards collision and are narrow enough to remain true long term.
- [ ] **Failure/recovery:** fail-open/fail-closed behavior, rollback/replay, and machine-readable errors are intentional.
- [ ] **Performance/scale:** complexity and hostile-input behavior were considered at materially larger scale.
- [ ] **Developer/operator UX:** CLI/API/schema/docs/examples/CI naming and shortest reproduction path stay coherent.
- [ ] **Long-horizon integrity:** accidental promises, migration burden, irreversible identifiers, and better future abstractions were considered.

Full rubric: [`ENGINEERING_GATE.md`](../ENGINEERING_GATE.md)

## Contracts touched

List schemas, protocol identifiers, CLI/API behavior, wire formats, public files, or persistent evidence formats changed by this PR. Write `none` only if genuinely none.

## Compatibility and migration

State backward compatibility, downgrade behavior, migration requirements, and rollback path.

## Failure modes

What new failures become possible, and how are they surfaced?

## Security impact

Describe new trust/input/authority boundaries. Write `none` only after considering abuse cases.

## Evidence and claim impact

What can now be claimed that could not be claimed before? Link the shortest reproducible evidence. If no public claim changes, say so.

## Tests and reproduction

Give the exact shortest commands or URLs needed to reproduce the change.

## Deliberately not included

What tempting adjacent capability was left out because its abstraction, evidence, or contract is not ready?
