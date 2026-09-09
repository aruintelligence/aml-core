# ĀML Engineering Gate

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

ĀML changes are not judged by whether they add capability. They are judged by whether they improve the system **without creating hidden future debt**.

Every material change must survive all ten axes below before merge.

## 1. Architecture

- Does the change fit an existing layer, or is it creating a new architectural concept?
- Is responsibility located in the right module?
- Does it duplicate an existing primitive under a new name?
- Does it create circular dependency between syntax, meaning, policy, runtime, evidence, trust, browser, or deployment layers?

## 2. Contract and compatibility

- Which public or machine-readable contracts change?
- Is the change backward compatible?
- If behavior changes, is a version boundary explicit?
- Can an old client safely ignore the new field or capability?
- Is downgrade behavior defined?

## 3. Security and abuse resistance

- What new input is trusted?
- What happens with malformed, adversarial, oversized, replayed, stale, conflicting, or partially valid input?
- Are fail-open and fail-closed choices intentional?
- Does the change accidentally turn metadata into authority?

## 4. Determinism and reproducibility

- Can two independent implementations produce the same observable result?
- Are timestamps, ordering, randomness, locale, floating point, Unicode, and serialization rules explicit where relevant?
- Is test evidence reproducible from a pinned commit?

## 5. Evidence and claims

- Does every new SHIPPED claim point to executable or inspectable evidence?
- Does the wording say exactly what was proved and no more?
- Are prototype, certification, standards, adoption, safety, compliance, and ethics boundaries preserved?

## 6. Interoperability and standards collision

- Does the name collide with an existing standard, protocol, security term, accessibility term, or serialization format?
- If ĀML intentionally differs from an existing standard, is that difference explicit?
- Are wire identifiers and protocol names narrow enough to remain true in five years?

## 7. Failure and recovery

- What happens when the feature fails halfway through?
- Can state be rolled back or replayed safely?
- Are errors machine-readable where needed?
- Can operators distinguish invalid input, unsupported capability, policy denial, transport failure, and internal failure?

## 8. Performance and scale

- What grows with number of nodes, policies, receipts, sessions, witnesses, or federated systems?
- Is complexity bounded or documented?
- Can a hostile input trigger pathological work or memory use?
- Does the feature still make sense at 10×, 100×, and 10,000× current demo scale?

## 9. Developer and operator usability

- Can a new implementer discover the feature from the normal entry points?
- Is there one shortest reproduction path?
- Are names consistent across CLI, API, schema, docs, examples, and CI?
- Are migration and debugging paths clear?

## 10. Long-horizon integrity

- What accidental promise does this change make to future versions?
- Which identifiers become difficult to rename after adoption?
- Could this block a better design later?
- Is the current abstraction the smallest durable one?
- Would we still be comfortable defending this contract to a standards engineer, security reviewer, enterprise architect, and independent implementer five years from now?

## Merge rule

A material change is not ready because tests pass. Tests are necessary, not sufficient.

Before merge, the PR must state:

1. the contracts touched;
2. the compatibility story;
3. new failure modes;
4. claim/evidence impact;
5. security impact;
6. interoperability impact;
7. performance impact;
8. migration or rollback path;
9. tests/evidence added;
10. what was deliberately **not** added because the abstraction is not ready.

If any answer is unknown, the change stays experimental or remains unmerged.
