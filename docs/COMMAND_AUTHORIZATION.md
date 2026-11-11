# Command exit status and authorization

**Breaking change (Unreleased).** A successful verification command must never
imply authorization unless the complete authorization decision is explicitly
true. `valid: true` reports internal consistency or integrity of an artifact.
It does not say that the relying party's own trust inputs (pinned root or
fingerprint, trusted key, retained challenge, held policy, trusted clock) were
satisfied.

## Exit contract

| Exit | Meaning |
| --- | --- |
| `0` | `authorized === true` **and** `authorization.authorized === true` (decision mode). In `--diagnostic-only` mode: a consistent result, never an authorization. |
| `3` | Consistent (`valid: true` or requested conditions met) but **not authorized**. Not a success. |
| other non-zero | Unchanged per command: invalid artifact, usage, unreadable input or runtime error. |

Every decision-mode report includes `valid`, `authorized`, `authorization`
(`aml-authorization-decision/1`: `decision`, `reasons`, `required`) and
`remaining_trust_assumptions`. Each required condition must be an own
property that is exactly `true`; missing, unknown, non-boolean or inherited
conditions, and evaluation errors, deny.

### Diagnostic-only mode

`--diagnostic-only` keeps the previous "exit 0 when consistent" behaviour for
conformance harnesses and dashboards. Its output always has
`authorized: false`, `diagnostic_only: true` and
`decision_use: "NOT AN AUTHORIZATION DECISION"`, and prepends the reason
`AML_AUTHZ_DIAGNOSTIC_ONLY` where the command reports reasons. Do not gate
execution, deployment or release on a diagnostic-only exit.

### Clock rule

Commands trust only the verifier's own clock. A caller-supplied time
(`--now`, `AML_VERIFY_AT`) is reported but cannot authorize unless it is
within 1 second of the local clock (JavaScript and Python witness
verifier). The Go verifier never treats `--now` as trusted.

## Per-command changes

| Command | Authorized (exit 0) only when | Old exit | New exit |
| --- | --- | --- | --- |
| `aml-governance-disclosure-verify` | valid and `--expected-merkle-root` (64 lowercase hex) equals the disclosure Merkle root | 0 valid, 2 invalid, 1 error | 0 authorized, 3 valid not authorized, 2 invalid, 1 usage/error |
| `aml-governance-disclosure-signed-verify` | valid, key in `--trusted-fingerprints` and not revoked, and `--required-scope` equals the signature scope | 0 valid, 2 invalid, 1 error | 0 / 3 / 2 / 1 |
| `aml-governance-transcript-verify` | never: an unsigned transcript has no authenticated source | 0 valid (implicit), 2 invalid, 1 error | 3 valid, 2 invalid, 1 error |
| `aml-governance-transcript-signature-verify` | valid, key in `--trusted-fingerprint`, and `--expected-key-id` equals the key id | 0 valid (implicit), 2 invalid, 1 error | 0 / 3 / 2 / 1 |
| `aml-release-profile validate` | never: structure only | 0 valid, 1 invalid, 2 usage | 3 valid, 1 invalid, 2 usage |
| `aml-release-profile verify <profile> <sha256>` | valid and the 64-hex expected value equals the profile SHA-256 | 0 valid, 1 invalid, 2 usage | 0 / 3 / 1 / 2 |
| `aml verify-brand-authorization` | valid, issuer equals `AML_EXPECTED_BRAND_ISSUER`, key SHA-256 equals new `AML_TRUSTED_BRAND_KEY_SHA256`, a revocation registry argument is supplied, and `AML_VERIFY_AT` is unset or within 1 s | 0 valid, 1 invalid | 0 / 3 / 1 |
| `aml verify-signed-quorum` | `authorized` (valid, threshold, requested conditions, held policy met, witness requirement met) | 0 requested conditions met, 2 unmet, 1 usage | 0 authorized, 3 met not authorized, 2 unmet, 1 usage |
| `independent/python/verify_signed_quorum.py` | same as `aml verify-signed-quorum` | 0 met, 2 unmet, 1 usage | 0 / 3 / 2 / 1 |
| `scripts/check-external-verifier-kit.mjs` | valid and new `--expected-root-sha256` equals the manifest root | 0 valid, 1 invalid | 0 / 3 / 1 |
| `scripts/validate-witness-record.mjs` | never: a witness record still requires human review | 0 valid, 1 invalid, 2 usage/parse | 3 valid, 1 invalid, 2 usage/parse |
| `scripts/witness-record-gate.mjs` and `actions/witness-record` | never (as above) | 0 valid, 1 invalid, 2 usage/parse | 3 valid, 1, 2; the Action runs `--diagnostic-only` and adds outputs `authorized=false`, `decision-use` |
| `independent/python/verify_witness.py` | valid, `--challenge` held challenge matched, and trusted clock | 0 valid, 1 invalid | 0 / 3 / 1 |
| `independent/go` (`verify.sh`, `main.go`) | never: no held-challenge support | 0 valid, 1 invalid, 2 input error (`verify.sh` collapsed non-zero to 1) | 3 valid, 1 invalid, 2 input error; `verify.sh` now preserves the exit code |
| `independent/python/wire_runtime.py verify` | never: no trust roots | 0 valid, 1 invalid | 3 consistent, 1 invalid |

### Directive 011 extension

The remaining artifact-verification and compatibility commands now follow the
same explicit diagnostic contract: `aml verify`, `verify-receipt`,
`replay-receipt`, `verify-signed-receipt`, `verify-policy-pack`, `verify-audit`,
`verify-attestation`; `aml-meaning verify-manifest`, `verify-attestation` and
meaning comparison; `aml-release-proof` verification (including `trusted` and
`verify-in-toto`); `aml-release-quorum verify`; `aml-github-attestation`;
`aml-brand-verify`; `aml-governance-witness-quorum`; the semantic-release gate;
and Python `wire_runtime.py negotiate`.

A consistent result exits **3**, with `authorized: false`. An explicitly supplied
`--diagnostic-only` exits 0 for consistency and labels the output. Invalid
artifacts keep their failure codes. Existing `verified`, `accepted`,
`quorum_met`, `claim_verified` and `equivalent` fields retain their diagnostic
meanings. These commands do not implement a protected-effect execution authority;
even a pinned release policy or key is not such an authority. Library return
values and published signed wire material are unchanged. `aml verify` now emits
a JSON report rather than the old human-readable checklist.

The shared outcome helper rejects incomplete or contradictory decision objects:
both flags, the `/1` schema, `allow`, nonempty unique required-condition names,
and the sole `AML_AUTHZ_ALLOW` reason must agree. It snapshots own data properties
without invoking accessors. Rejected decision outputs normalize both flags to
false. This is defense in depth inside a **trusted** verifier, not proof of
permission when a malicious host can construct arbitrary JSON.

`aml verify-brand-authorization` additionally requires
`AML_TRUSTED_BRAND_REVOCATION_SHA256`: lowercase SHA-256 of the exact UTF-8
registry bytes, provisioned by the relying party independently of the request.
Missing or substituted registries cannot authorize. A trusted administrator
can still pin stale data; no live registry service, freshness protocol or
rollback-resistant policy distributor is implemented here. Duplicate keys in
credential/registry JSON fail before verification.

## Migration

- If you gated execution on exit 0 of any command above, supply the trust
  inputs listed in the table and keep gating on exit 0; also check
  `authorized === true` in the JSON.
- If you only need the old consistency signal (conformance runs, dashboards),
  add `--diagnostic-only` and do not use the result as permission.
- Treat exit `3` as failure in shell (`set -e`) and CI. Scripts that tested
  `[ $? -eq 0 ]` remain fail-closed; scripts that tested `[ $? -ne 1 ]` or
  `!= 2` must be updated.
- External verifiers taking the published challenge are unaffected: the locked
  black-box contract still expects exit 0 for a valid bundle. AML's own
  Python and Go reference verifiers satisfy it in `--diagnostic-only` mode
  (`protocol/verifiers/*-reference-claim.json`).

## Static check

`scripts/check-valid-field-decisions.mjs` enumerates every read of a `valid`
field and every exit-0 / HTTP-2xx decision sink in JavaScript, Python and Go,
and fails on a positive sink controlled by `valid` alone. Before matching it
rewrites valid-derived aliases (variables, destructuring, subscripts, object
properties, `Object.assign`, helper and arrow-function returns, functions
imported from relative modules; Python through an AST pass) to a `.valid`
read. Reviewed `--diagnostic-only` exits must stay under their guard.

Limits: values passed as call arguments or held in containers, computed
property names, non-relative imports, and expressions split across lines are
not followed; Go is matched lexically. It is a static approximation, not a
proof.

## Scope still open

The static checker remains an approximation focused on `valid`; its six
previously documented data-flow limitations are not closed by this change.
Dynamic module loading, external consumers and every application-specific
execution route require separate review. HTTP status 200 on an evaluation API
is transport success, not a general execution capability. Build/lint/creation,
help and version commands can exit 0 without being authorization gates.

The main CI build-manifest step explicitly uses diagnostic mode. Existing
brand/release/quorum/meaning composite Actions are **not silently opted into**
diagnostic mode: their default commands now fail closed with exit 3. Consumers
must deliberately migrate their consistency checks and must not use diagnostic
success or a `verified` output alone as release/deployment permission. A full
redesign of their release-authorization interfaces remains open.

## Remaining trust assumptions

Pinned roots, fingerprints, key ids and scopes are only as good as the
channel they came from. A trusted key does not establish real-world signer
identity. The brand registry pin binds exact supplied bytes; trusted provisioning and
freshness of that pin remain deployment assumptions. The local clock is trusted.
