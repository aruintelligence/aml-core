# ĀML Engineering Gates

Status: project engineering discipline for substantive changes.

Author: Daniel Jacob Read IV  
Steward: ĀRU Intelligence Inc.™

ĀML should not optimize for commit count. It should optimize for durable correctness, reproducibility, interoperability, and defensible public claims.

Every substantive change SHOULD be evaluated against all ten gates below before merge. Protocol, trust, receipt, policy, security, conformance, wire, release, and public-claim changes MUST explicitly satisfy them or document why a gate does not apply.

## Gate 1 — Semantic correctness

Does the change do exactly what its name, API, protocol identifier, documentation, and examples say it does?

Check edge cases, invalid inputs, deterministic behavior, hidden coercions, default values, and contradictory semantics.

## Gate 2 — Backward compatibility

Could an existing valid ĀML source file, API consumer, CLI user, browser bridge, receipt verifier, policy pack, wire consumer, or published example break?

If yes, define migration behavior and version boundaries before merge.

## Gate 3 — Interoperability

Could an independent implementation reproduce the behavior without importing the reference runtime?

Normative behavior should have versioned identifiers, vectors, or observable black-box contracts when practical.

## Gate 4 — Security and abuse resistance

Consider malformed input, resource exhaustion, replay, substitution, downgrade, confused-deputy behavior, path/network boundaries, signature misuse, trust escalation, unsafe defaults, injection, and hostile data.

A green happy path is not sufficient evidence of safety.

## Gate 5 — Evidence and reproducibility

Can a skeptical third party reproduce the claim from source, fixtures, commands, vectors, receipts, or other stable evidence?

Important claims should survive without trusting a screenshot, prose description, or the live website.

## Gate 6 — Versioning and future migration

Is the name narrow enough to remain true years later?

Avoid identifiers that accidentally claim a complete standard when only a subset exists. Decide whether future expansion is additive, revisioned, or requires a new protocol/version before publishing the current identifier.

## Gate 7 — Claim discipline

Does public wording distinguish SHIPPED, experimental, draft, proposed, reference implementation, self-declaration, and external adoption?

Never convert internal capability into implied certification, standards recognition, independent adoption, security approval, or objective human-outcome claims without evidence.

## Gate 8 — Test depth

Test positive behavior, boundaries, must-reject cases, cross-language agreement where relevant, tampering/failure paths, and regression compatibility.

A test should fail when the protected contract is intentionally broken.

## Gate 9 — Discoverability and documentation consistency

Do README, API docs, protocol manifests, examples, issue forms, schemas, CI names, publications, release notes, and machine-readable surfaces agree?

A new protocol is not complete while stale names or contradictory scopes remain elsewhere.

## Gate 10 — 5,000-step consequence review

Ask what happens when ĀML has multiple independent runtimes, enterprise deployments, third-party policy packs, security researchers, standards discussions, archived releases, old receipts, adversarial implementers, and years of compatibility history.

Prefer decisions that reduce future ambiguity and migration cost even when they require more precision today.

## Merge rule

Before merging a high-impact change, answer:

1. What contract changed?
2. What existing behavior could break?
3. What invalid/adversarial behavior was tested?
4. What independent evidence exists?
5. What public claim is now justified—and what claim is still not justified?
6. What version identifier freezes this behavior?
7. What would we regret about this decision after five years of adoption?

If any answer is unclear, the change is not finished.

## Perfection is approached through falsification

ĀML cannot honestly promise literal perfection. The engineering target is stronger: continuously try to disprove our own assumptions before outsiders have to.

Every contradiction found before merge is a project improvement, not a failure.
