# AML Verifier Contract Snapshot Versioning

**SPEC — experimental project policy.**

The AML verifier contract is intentionally snapshot-based.

## Rule 1 — Published snapshots are immutable historical targets

A snapshot identifies:

- one exact Git commit;
- one exact ordered path set;
- one canonicalization profile;
- one witness artifact schema;
- one required behavior set.

Once published, the meaning of that snapshot ID must not be changed in place.

## Rule 2 — Locked path drift requires a new snapshot

If any path listed in the active snapshot changes byte-for-byte relative to the snapshot source commit, CI must fail.

The correct response is not to weaken the guard. Publish a new snapshot ID anchored to the intended contract state.

## Rule 3 — Old snapshots remain valid historical comparison points

A new snapshot does not rewrite the old target. Independent implementations may continue to report compatibility with an older snapshot.

## Rule 4 — Compatibility claims name the exact snapshot

Prefer:

```text
implements aml-verifier-contract-2026-09-08-01
```

over:

```text
supports AML verifier v1
```

The snapshot is more precise.

## Rule 5 — A snapshot change is not automatically a breaking language release

Verifier contract snapshots are narrower than the AML language version. A new verifier snapshot can be published without claiming a new stable AML language release.

## Rule 6 — Compatibility is evidence, not certification

Snapshot agreement, conformance PASS, signatures, or verifier quorum do not imply standards-body approval, institutional independence, policy correctness, truthful intent, or official AML trademark authorization.
