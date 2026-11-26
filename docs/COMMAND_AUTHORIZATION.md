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
(`--now`, `AML_VERIFY_AT`) is reported but never authorizes (Directive 010;
the earlier 1-second tolerance let a caller backdate a credential that had
just expired). A non-finite local clock also denies. The Go verifier never
treats `--now` as trusted.

## Per-command changes

| Command | Authorized (exit 0) only when | Old exit | New exit |
| --- | --- | --- | --- |
| `aml-governance-disclosure-verify` | valid and `--expected-merkle-root` (64 lowercase hex) equals the disclosure Merkle root | 0 valid, 2 invalid, 1 error | 0 authorized, 3 valid not authorized, 2 invalid, 1 usage/error |
| `aml-governance-disclosure-signed-verify` | valid, key in `--trusted-fingerprints` and not revoked, and `--required-scope` equals the signature scope | 0 valid, 2 invalid, 1 error | 0 / 3 / 2 / 1 |
| `aml-governance-transcript-verify` | never: an unsigned transcript has no authenticated source | 0 valid (implicit), 2 invalid, 1 error | 3 valid, 2 invalid, 1 error |
| `aml-governance-transcript-signature-verify` | valid, key in `--trusted-fingerprint`, and `--expected-key-id` equals the key id | 0 valid (implicit), 2 invalid, 1 error | 0 / 3 / 2 / 1 |
| `aml-release-profile validate` | never: structure only | 0 valid, 1 invalid, 2 usage | 3 valid, 1 invalid, 2 usage |
| `aml-release-profile verify <profile> <sha256>` | valid and the 64-hex expected value equals the profile SHA-256 | 0 valid, 1 invalid, 2 usage | 0 / 3 / 1 / 2 |
| `aml verify-brand-authorization` | valid, issuer equals `AML_EXPECTED_BRAND_ISSUER`, key SHA-256 equals `AML_TRUSTED_BRAND_KEY_SHA256`, a revocation registry argument is supplied and its canonical SHA-256 equals `AML_TRUSTED_REVOCATION_REGISTRY_SHA256` (rollback protection), and `AML_VERIFY_AT` is unset | 0 valid, 1 invalid | 0 / 3 / 1 |
| `aml verify-signed-quorum` | `authorized` (valid, threshold, requested conditions, held policy met, witness requirement met) | 0 requested conditions met, 2 unmet, 1 usage | 0 authorized, 3 met not authorized, 2 unmet, 1 usage |
| `independent/python/verify_signed_quorum.py` | same as `aml verify-signed-quorum` | 0 met, 2 unmet, 1 usage | 0 / 3 / 2 / 1 |
| `scripts/check-external-verifier-kit.mjs` | valid and new `--expected-root-sha256` equals the manifest root | 0 valid, 1 invalid | 0 / 3 / 1 |
| `scripts/validate-witness-record.mjs` | never: a witness record still requires human review | 0 valid, 1 invalid, 2 usage/parse | 3 valid, 1 invalid, 2 usage/parse |
| `scripts/witness-record-gate.mjs` and `actions/witness-record` | never (as above) | 0 valid, 1 invalid, 2 usage/parse | 3 valid, 1, 2; the Action runs `--diagnostic-only` and adds outputs `authorized=false`, `decision-use` |
| `independent/python/verify_witness.py` | valid, `--challenge` held challenge matched, and trusted clock | 0 valid, 1 invalid | 0 / 3 / 1 |
| `independent/go` (`verify.sh`, `main.go`) | never: no held-challenge support | 0 valid, 1 invalid, 2 input error (`verify.sh` collapsed non-zero to 1) | 3 valid, 1 invalid, 2 input error; `verify.sh` now preserves the exit code |
| `independent/python/wire_runtime.py verify` | never: no trust roots | 0 valid, 1 invalid | 3 consistent, 1 invalid |

### Directive 010 additions

No verification field (`verified`, `accepted`, `quorum_met`, `official`,
`claim_verified`) is permission. Each command below now reports `authorized`
and an `aml-authorization-decision/1` object and exits 0 only when it is true.

| Command | Authorized (exit 0) only when | Old exit | New exit |
| --- | --- | --- | --- |
| `aml verify <build_manifest.json>` | verified and `--expected-sha256` equals the manifest file SHA-256 | 0 verified, 1 | 0 / 3 / 1 |
| `aml verify-receipt`, `aml replay-receipt` | verified (replay matches) and `--expected-sha256` equals `receipt_sha256` | 0 verified, 1 | 0 / 3 / 1 |
| `aml verify-signed-receipt`, `aml verify-policy-pack` | verified and `--trusted-key-sha256` equals the signing key SHA-256 | 0 verified, 1 | 0 / 3 / 1 |
| `aml verify-audit` | verified and `--expected-sha256` equals the head entry hash (a truncated stream does not match) | 0 verified, 1 | 0 / 3 / 1 |
| `aml-meaning verify-manifest` / `verify-attestation` | `--expected-root-sha256` equals the manifest root / `--trusted-key-sha256` equals the attestation key | 0 verified, 1 | 0 / 3 / 1 |
| `aml-release-proof <proof>` / `verify-in-toto` | verified and `--expected-sha256` equals `proof_sha256` | 0 verified, 1 | 0 / 3 / 1 |
| `aml-release-proof trusted` | verified, the policy fingerprint is valid and the expected-policy argument equals it | 0 verified, 1 | 0 / 3 / 1 |
| `aml-release-quorum verify` | quorum verified and `--policy-sha256` equals the policy fingerprint (a mismatch is exit 1) | 0 verified, 1 | 0 / 3 / 1 |
| `aml-brand-verify` | official against trust roots **and** a revocation registry checked and pinned by `AML_TRUSTED_REVOCATION_REGISTRY_SHA256`; claim mode also needs `claim_verified` | 0 official, 1 | 0 / 3 / 1 |
| `aml-governance-witness-quorum` | quorum met, `--expected-policy-sha256` equals the canonical input policy, the policy lists trusted keys, and no conflicting roots | 0 quorum met, 1/2 | 0 / 3 / 2 unmet / 1 |
| `aml-github-attestation` | `gh` verified, the attestation layer verified, and `--authorization-profile-sha256` equals the profile fingerprint | 0 verified, 1 | 0 / 3 / 1 |
| `scripts/semantic-release-gate.js` and `actions/semantic-release-proof` | verified and `--trusted-key-sha256` / `AML_TRUSTED_RELEASE_KEY_SHA256` / input `trusted-key-sha256` equals the release key; output `authorized` | 0 verified, 1 | 0 / 3 / 1 |
| `actions/semantic-release-quorum` | `authorized` from `aml-release-quorum`; `policy-sha256` is required in practice | 0 verified | 0 / 3 / 1 |
| `independent/python/wire_runtime.py negotiate` | never: the remote capability document is unauthenticated | 0 accepted, 1 | 3 accepted, 1 rejected; 0 only with `--diagnostic-only` |
| HTTP `POST /v1/verify-receipt` | verified and body `expected_receipt_sha256` equals `receipt_sha256` | 200 verified | 200 authorized, 422 otherwise |
| HTTP `POST /v1/verify-brand-authorization` | official and the server-held revocation registry was checked | 200 official | 200 / 422 |
| HTTP `POST /v1/evaluate`, `/v1/deployment/evaluate` | `/v1/evaluate` never (caller-chosen profile); deployment adds an explicit decision (evaluation ok, policy allowed, server policy locked) without changing its status code | 200 | `authorized` field added |

Composite Actions (`meaning-gate`, `meaning-lock`, `meaning-manifest`,
`semantic-release-proof`, `semantic-release-quorum`, `verify-official`,
`witness-record`) no longer interpolate `${{ inputs.* }}` into `run:` shell
text; inputs pass through `env:` (script-injection fix).

### Library: capability tokens

`verifyCapabilityToken(...).valid` means only "signed by the key embedded in
the token"; anyone can mint one. New `authorizeCapabilityToken(token, {
trustedIssuerKeySha256, audience, subject, sessionId, intentSha256,
requiredCapability, consumptionGuard })` returns `authorized: true` only when
the issuer key is pinned, the token is unexpired on the local clock (no
caller time is accepted), audience, executor (`subject`), `session_id` and
`intent_sha256` all equal the relying party's expectations, the capability
is granted, and the nonce is unconsumed in the supplied guard; the returned
guard records the consumption. `signCapabilityToken` accepts optional
`session_id` and `intent_sha256` (omitted when null, so existing signatures
are unchanged).

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

Directive 010 adds a rule that any shipped exit/HTTP success sink gated only
on verification fields (`verified`, `accepted`, `quorum_met`, `official`, ...)
fails unless an `authorized` decision gates it or it is listed in
`REVIEWED_NON_AUTHORIZATION_SINKS` / `REVIEWED_DIAGNOSTIC_EXITS` with a reason.

Limits of the lexical check: values passed as call arguments or held in
containers, computed property names, non-relative imports, and expressions
split across lines are not followed; Go is matched lexically.

### Data-flow check (CodeQL)

`tooling/codeql/{javascript,python,go}/VerificationWithoutAuthorization.ql`
use CodeQL global taint tracking from verification-field reads (including
computed names such as `r[k]` with a constant `k`, `Reflect.get(r, k)`,
`getattr(r, k)` and Go `reflect.Value.FieldByName`) through calls, returns,
containers (including JavaScript `Map` set/get), imports and multi-line
expressions to exit/HTTP status sinks and to conditions guarding privileged
calls. A sink is reported unless the authorization decision controls it:

- a guarding condition is split into operands; it is accepted only when an
  operand that must hold (an `&&` / `and` conjunct, not an `||` / `or`
  alternative and not a negation) carries `authorized`;
- a conditional status (`a ? 0 : b ? 0 : 1`, `0 if a else 1`) is checked per
  success branch: an `authorized` read on another branch does not count;
- in JavaScript, a dominating guard such as
  `if (r.authorized !== true) return deny();` counts (polarity-aware);
- exit statuses that can never be a success (`3 if ok else 1`, a module
  constant such as `EXIT_NOT_AUTHORIZED = 3`, or a call to a function that
  only returns such values) are not sinks.

`node scripts/check-authorization-dataflow.mjs` (needs `CODEQL_CLI`; fails
closed with exit 2 otherwise) runs them on the seeded corpus
`tooling/codeql/authz-bypass-fixtures.json` (bypasses in eleven categories
plus authorized controls for every language); `--repo` prints every alert in
this repository and `--repo-gate audit/AML_AUTHZ_DATAFLOW_REVIEW.json` fails on
any alert that is not in the reviewed inventory, on any stale inventory entry,
and on any CodeQL/LGTM source suppression comment. The workflow
`.github/workflows/codeql-authorization-dataflow.yml` runs both.

These queries and the lexical check are a defense-in-depth aid, not the
enforcement boundary, and they have known blind spots — for example
dynamically computed property access and flows across process or file
boundaries. Runtime authorization is the enforcement boundary: a success
outcome is permitted only when the complete authorization decision is
explicitly true. The reviewed inventory is per sink line: a later change
that adds a second flow into an already reviewed sink is not separately
reported.

## Remaining exceptions

The commands previously listed here are covered by "Directive 010
additions". `POST /v1/deployment/batch` now reports per-item and batch-level
`authorized` (server-locked policy only), and the Python evidence verifiers
exit 0 only with `--expected-policy-sha256` matching the canonical trusted
policy (`python3 independent/python/authorization_cli.py policy-sha256
<policy.json>`); verified-but-unpinned exits 3. Still open: the reviewed
non-authorization sinks in `scripts/check-valid-field-decisions.mjs`
(repair, drill, doctor, support-bundle, pilots) exit 0 on consistency by
design and must not be used as gates.

## Remaining trust assumptions

Pinned roots, fingerprints, key ids, scopes and registry digests are only as
good as the channel they came from; a compromised host that can rewrite them
can authorize anything (see the `LIMIT:` tests in
`test/directive010-trust-boundaries.test.js`). A trusted key does not
establish real-world signer identity, and a stolen pinned key still
authorizes. A registry pin prevents substitution and rollback relative to the
pinned digest but does not prove the pinned registry is the newest one
(freshness depends on how the relying party updates the pin). Verifier
commands are stateless: the same pinned artifact verifies on every replay;
single use is enforced only where a consumption guard is kept
(`authorizeCapabilityToken`, the action-boundary grant store), and only as
durably as that guard is stored. The local clock is trusted.
