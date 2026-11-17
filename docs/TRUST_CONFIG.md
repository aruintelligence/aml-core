# Signed trust config and durable single use

Status: local candidate (branch `trust-config`). Established techniques only:
The Update Framework (TUF) root metadata (threshold signatures, root
rotation, version-based rollback protection, expiry), append-only local state,
a persisted time floor, and exclusive-create + fsync single-use records.

## Why

Before this change every verifier took its trust from per-invocation pins
(`--trusted-key-sha256`, `--expected-sha256`, `AML_TRUSTED_*`). Whoever controls
the command line controls the pins, a stolen key could not be revoked, a pinned
revocation registry could not be shown to be current, and a pinned artifact
authorized on every replay.

## The trust config

A signed envelope `{ signed, signatures }`. `signed` is:

| field | meaning |
| --- | --- |
| `type` | `aml-trust-config/1` |
| `version` | integer >= 1; must never decrease (rollback protection) |
| `issued_at`, `expires_at` | ISO-8601 UTC; evaluated on the verifier's own clock |
| `root` | `{ threshold, keyids }` root key fingerprints (SHA-256 of SPKI DER) |
| `trusted_keys` | `[{ keyid, roles }]`, roles from `receipt`, `policy-pack`, `build-attestation`, `brand-authorization`, `capability-issuer` |
| `revoked_keys` | key fingerprints; revocation is sticky across versions |
| `policy_sha256`, `registry_sha256`, `profile_sha256` | digests the relying party accepts (`null` pins nothing) |
| `require_single_use` | when `true`, verifiers and capability tokens must use a durable single-use store |

Unknown fields are refused. A config is trusted only when **all** hold:
threshold of the current root signed it (each key counted once); if it rotates
the root, a threshold of the new root signed it too; its version is not lower
than the highest accepted version and the same version has the same digest; no
caller-supplied time is present; the local clock is not earlier than the
persisted time floor, not earlier than `issued_at`, and earlier than
`expires_at`; and the new state was persisted.

## Enrolling a host

```sh
aml trust-init /etc/aml/trust --threshold 2 --root-key-sha256 <k1>,<k2>,<k3>
aml trust-sign config-body.json root1.pem,root2.pem config.json   # offline, on the signing hosts
aml trust-verify --trust-config config.json
```

The anchor is written once (exclusive create). Accepted versions are appended
under `versions/` and never rewritten. `/etc/aml/trust` is always consulted;
`$AML_TRUST_STATE_DIR` or `--trust-state` can add another enrolled directory but
cannot remove the system one. Make the system directory root-owned and
read-only to the account that runs verifiers.

## Verifiers

`verify`, `verify-receipt`, `replay-receipt`, `verify-signed-receipt`,
`verify-policy-pack`, `verify-attestation`, `verify-audit` and
`verify-brand-authorization` accept `--trust-config <file>`.

- **Not enrolled, no `--trust-config`:** unchanged; explicit pins are required
  exactly as before.
- **Enrolled host:** `--trust-config` is required; without it the command is not
  authorized (exit 3).
- **Trust-config mode:** signing keys must be trusted by the config for the
  command's role and not revoked. Explicit flag/env pins still apply and must
  match as well (AND). Artifact-digest pins (`--expected-sha256`) are still
  required for artifact verifiers. `verify-brand-authorization` takes the
  registry pin from `registry_sha256`. `verify-policy-pack` also requires
  `pack_sha256 == policy_sha256` when the config sets it.

`verify-witness` and `verify-signed-quorum` accept the same three flags. Their
own decision is ANDed with `trust_config_trusted` (and single use); the single
use artifact is the SHA-256 of the bundle or quorum file bytes, so a bundle
consumed by one language's verifier is refused by the others sharing the store.

`deploy` in trust-config mode also requires the policy profile digest to equal
`profile_sha256` (compute it with `aml profile-sha256 <profile>`; a null
`profile_sha256` denies) and refuses a caller-supplied `--timestamp`.

### Python and Go

`independent/python/trust_config.py` and `independent/go/trustconfig.go`
implement the same evaluation with the standard library only (the Python
Ed25519 check is a pure-Python RFC 8032 verifier). They read and write the
same state directory and single-use store layout as JavaScript.

- Python evidence verifiers (`verify_evidence_capsule.py`,
  `verify_evidence_archive.py`, `verify_evidence_migration.py`,
  `verify_http_exchange.py`, `evidence_repair_record.py verify`) accept the
  three flags. In trust-config mode the config must be trusted and, when it sets
  `policy_sha256`, the policy digest must equal it (ANDed with any
  `--expected-policy-sha256`).
- `verify_witness.py` and `verify_signed_quorum.py` behave like their
  JavaScript counterparts above.
- The Go witness verifier reports the trust decision and adds
  `AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED` on an enrolled host, but it still never
  authorizes.
- `trust_config.py trust-verify` and `aml-go-witness trust-verify` match
  `aml trust-verify` (exit 0 only when trusted).

Shared vectors in `conformance/trust-config/vectors.json` (regenerate with
`node conformance/trust-config/generate.mjs`) cover acceptance and every denial
check. `test/trust-config-parity.test.js` requires JavaScript, Python and Go to
produce identical results for every step.

Encodings are strict in every language: Ed25519 keys only, in canonical 44-byte
SPKI PEM armor; signatures in canonical padded base64 (one accepted spelling,
the same rule as every other ĀML signature verifier: `protocol/strictBase64.js`); calendar-exact UTC
timestamps (`YYYY-MM-DDTHH:MM:SS[.sss]Z`, year 1970 or later); duplicate JSON
keys refused.

## Single use

`--single-use-store <dir>` (or `require_single_use: true` in the config) makes a
verified artifact authorize at most once. With a trusted config, the store in
each enrolled trust state directory (`<state-dir>/single-use/`) is always used
as well, so choosing a different or empty `--single-use-store` cannot reopen a
consumed artifact; `--single-use-store` only adds a store, and the artifact
must be newly consumed in every store. Library callers pass
`consumptionStore: openDurableConsumptionStore(dir)` to `authorizeCapabilityToken`.
The record is created with `O_CREAT|O_EXCL`, written and fsync'd, and the
directory fsync'd, before authorization is reported. A crash after the create
burns the authorization (at-most-once). Use a local filesystem with atomic
`O_EXCL`.

## Breaking changes

- On a host with an enrolled trust state directory, verifier commands invoked
  without `--trust-config` now exit 3 instead of 0.
- `authorizeCapabilityToken` with a trust config whose `require_single_use` is
  true (or with an untrusted config decision) no longer accepts an in-memory
  consumption guard alone.
- New flags (`--trust-config`, `--trust-state`, `--single-use-store`) are no
  longer treated as positional arguments.
- The enrolled-host rule also applies to `verify-witness`,
  `verify-signed-quorum` and the Python verifiers.
- Trust configs signed with non-Ed25519 keys, non-canonical PEM or base64,
  or timestamps such as `2026-02-30` or `24:00` are refused.
- `deploy` in trust-config mode requires a pinned `profile_sha256`.

## What this does not solve

A host where an attacker has root or write access to trust state is out of
scope for this design: no software on that host can protect its own trust
store. Verification on a separate host, or hardware attestation, is future
work. A stolen threshold of root keys, and the verifier host clock, remain
trust assumptions.
