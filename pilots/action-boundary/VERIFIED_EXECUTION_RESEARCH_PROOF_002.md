# ĀML Verified Execution — Research Proof 002 (experimental, partial)

Starting local commit: `d526581e0b23ef574ca623ff8a686ac97c3ea75a` on `operation-aml/grant-store-integrity-20261104`. This unit extends Proof 001; it does not replace the negative fixtures there. Verify the final commit from Git after checkout. Run `node --test test/action-boundary-authorized-execution.test.js test/action-boundary-execution-gate.test.js` and `npm test`.

## Claim and boundary

**EXPERIMENTALLY DEMONSTRATED, within this fixture:** a route which calls `authorized_execution.consume` before inserting an effect row rejects an unsigned, forged, modified, expired, revoked, wrong-epoch or spent request, provided the issuer signing key, pinned issuer public-key digest and SQLite gate cannot be modified by the attacker and every effectful route uses this gate. The gate serializes claims under `BEGIN IMMEDIATE`; the committed unique operation row is the linearization point for one protected attempt. A provider request is exactly bound by SHA-256 of UTF-8 request bytes, signed operation ID, destination and effect. There is no claim that this produces exactly-once external execution.

| Boundary | Code | Assumption and failure |
| --- | --- | --- |
| Issuer to provider | `authorized_execution.py` verifies Ed25519 with `AML-AUTHORIZED-EXECUTION/1` domain prefix | Issuer controls private key and signs only a policy-approved action; this fixture does **not** evaluate ĀML policy or authenticate a human. A dishonest issuer can authorize any request. |
| Provider to gate | `authorized-provider-fixture.py` calls `consume` before effect insert | Provider is trusted to call it, no unmediated access exists, and process credentials cannot write gate/provider DB directly. These isolation conditions are **not enforced** in this one-identity local test. |
| Gate to effect | Two distinct SQLite DBs | Gate survives provider rollback. No atomic commit across them; crash after consumption before provider insert strands an operation. |
| Evidence | Gate claim and provider row | Neither is independently authenticated, and an ordinary local reader shares their administrator. There is no independently operated verifier or witness for this new route. |

## Wire contract in this experimental fixture

The signed statement has exactly these fields: `version` (`aml-authorized-execution/1`), `issuer`, `principal`, `policy_id`, `policy_epoch`, `operation_id`, `request_sha256`, `destination`, `effect`, `expires_at_ms`. The signature is Ed25519 over ASCII `AML-AUTHORIZED-EXECUTION/1` followed by a zero byte and compact JSON of the statement with lexicographically sorted keys and ASCII escaping. The request is UTF-8 JSON with exactly `operation_id`, `destination`, `effect`, `body`; duplicate object keys are rejected. The signature covers its exact bytes by digest. This is **not** the established ĀML `sorted-json-v1` wire protocol; it is a separate experimental profile. No stable protocol compatibility was changed. Key PEM hash and policy epoch are pinned when the authority is initialized and checked in the consumption transaction. Expiry relies on the local wall clock and has no rollback-resistant time authority.

The public key path supplied to the verifier must match the pinned hash. Because the local host can edit the file and authority DB under the same OS identity, this is an approximation of independent administration, **not** an independently operated trust domain. The issuer metadata strings are cryptographically bound but not checked against an identity directory. A valid signature means only that the private key signed the specified bytes.

The verifier captures the issuer PEM bytes once, uses those bytes for OpenSSL verification and compares their SHA-256 to the gate's pinned digest. This closes a file-swap window between separate key reads, assuming the SQLite gate itself remains trusted. A caller capable of replacing both the pinned gate and key remains outside the guarantee.

## Adversarial evidence and counterexamples

The focused test covers the protected path's signed positive, replay, destination and payload mutation, operation substitution, forged signature, key substitution, expiry, revocation, stale epoch, concurrent processes, duplicate JSON keys, provider-only history deletion and missing gate. The preexisting Proof 001 tests preserve **KNOWN TO FAIL** coordinated rollback and direct ungated route counterexamples. The old provider fixture and raw SQLite file remain accessible under the same identity; therefore a compromised host with those privileges can still write or call around the gate. There is no complete mediation guarantee in this repository fixture.

On the starting branch plus these four files, local `node --test test/action-boundary-authorized-execution.test.js test/action-boundary-execution-gate.test.js` passed 11/11 (0 failures); `npm test` passed 1,171/1,171 (0 failures or skips); `npm run check:links` passed across 450 Markdown files; `git diff --check` and Python syntax compilation passed. The initial focused run failed 2/9 because the test observer queried an effects table that correctly did not exist after all attack requests were rejected. The observer now counts that as zero; no enforcement check was weakened. CI for the new commit is **NOT RUN** at the time of this note.

Crash after claim commit but before effect insert still cannot be retried safely through this gate. The state is **CLAIMED / outcome uncertain**, not completed. Recovery requires external evidence or an operator decision. Coordinated provider-and-gate rollback can revive an authorization claim. A compromised issuer, compromised authority administrator, signing-key substitution at initial provisioning, direct DB write, clock rollback, or alternate provider route defeats or falls outside the demonstrated property. Missing independent observation prevents a verifier from proving that no other effect occurred.

## Formal, performance, novelty and disclosure status

**UNVERIFIED:** no model checker refinement, isolated process identities, separate verifier, rollout rollback matrix, or measured end-to-end latency for this new binding. The prior bounded model and Proof 001 tests do not prove this implementation. **Prior art:** Ed25519 signed capabilities, pinned keys, unique database claims, and reference monitors are established mechanisms. No novelty or patentability claim is made. This prototype combines them in a controlled AI-action fixture and exposes the complete mediation requirement. The MIT license, main branch and published releases are unchanged. Review potential new disclosure with founder and counsel before any broader public claim.

Next decisive experiment: move the provider/gate and key provisioner to credentials inaccessible to the AI host, remove all alternate effectful routes, and challenge the protected provider API from an actually compromised host. Retain an external authority or witness across rollback and test crash recovery with separate authenticated provider status. Until then, the primary Proof 002 objective is **PARTIALLY DEMONSTRATED** only.
