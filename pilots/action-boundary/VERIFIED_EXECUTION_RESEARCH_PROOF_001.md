# ĀML Verified Execution — Research Proof 001 (experimental)

Baseline: draft PR #468, branch `operation-aml/grant-store-integrity-20261104`, starting remote commit `7b9382b6d533ce2c3c0a928573a59f3b114d101d`. This document describes an in-repository E2 test fixture, not independent deployment, certification, novelty or production exactly-once execution. Run `node --test test/action-boundary-execution-gate.test.js` with Python 3; `npm test` runs the complete repository suite.

## Narrow claim and topology

The controlled provider's only effect is a SQLite row. Its optional gate opens an **already initialized, separate** SQLite database and consumes a unique operation ID with `BEGIN IMMEDIATE`, a unique key, and `COMMIT` before attempting the provider effect. Under the assumptions below, restoring or deleting only the provider's effect/idempotency row cannot permit a second effect through the gated route for that operation. This is established database transaction behavior composed with ĀML's experimental action-boundary fixture, not a new distributed consensus protocol.

| Boundary | Implementation | Trust assumption and evidence |
| --- | --- | --- |
| AI proposal to host approval | Existing guarded/action-boundary pilots | Host controls policy, canonical action, approval and dispatch. This test does not authenticate a human. |
| Host authorization to execution claim | Existing file authority and SQLite epoch coordinator | Their earlier tests cover spent grants. The new gate is **not yet bound to those grants**. |
| Provider entry to execution claim | `sqlite-provider-fixture.py` optionally calls `sqlite_execution_gate.py` | Every consequential provider route must call the gate, and its database must survive provider rollback. Commit of the claim is the local linearization point. |
| Gate to provider effect | Separate SQLite databases, non-atomic across them | Crash after gate commit but before effect strands the action. No automatic replay of an irreversible effect. |
| Provider effect to evidence | Provider row, signed status, witness/history verifier in companion fixtures | A provider signature proves a statement was signed, not physical execution. Prior signed records must be retained to detect conflicting effects after provider history loss. |

## Executable attack matrix

| Test condition | Observed result | Meaning |
| --- | --- | --- |
| Provider row deleted; gate retained; identical request repeated through gated route | `execution_claim_spent`, no second provider row | Duplicate effect prevented within gate-retention and enforced-route assumptions. |
| Provider and gate rows both deleted; identical request repeated | New effect ID | Coordinated rollback defeats local gate. |
| Provider row deleted; direct ungated provider route used | New effect ID | Alternate effectful entry point defeats mediation. |
| Gate consumed, provider exits before effect; request repeated | Repeat blocked, no effect | Safety at the cost of liveness. Requires operator investigation, not a success claim. |
| Gate database missing | Request rejected before effect | Fail closed within the fixture. |

The provider's default ungated route remains for previous experimental compatibility and as a deliberate bypass counterexample. A real integration must make gate enforcement mandatory at the provider's effect boundary and remove unmediated effectful access. The optional gate currently accepts a request digest from the provider; it does **not** validate the host's authorization or approved destination against an independent policy authority. The gate and provider share the same OS identity. It does not survive a coordinated administrator rollback, compromised gate, direct database mutation, or provider-side bypass.

## Small indistinguishability result

Suppose a provider can make an irreversible effect, then lose all durable records of it, while the client loses its acknowledgment. To the recovering client, history A (request never reached provider) and history B (effect occurred, then provider record and acknowledgment were lost) are identical. An automatic retry is safe in A but may duplicate the effect in B. No algorithm using only that identical client-visible state can both guarantee progress by retry and guarantee no duplicate effect. A separately retained execution claim can forbid retry in both histories (safety, lost liveness in A). A durable provider idempotency record or a separately trusted observation/reconciliation authority is needed for a stronger outcome claim. This argument assumes no other distinguishing information or nonrollbackable enforcement state.

## Formal properties and remaining experiment

Safety invariant for the bounded fixture: if all effectful provider requests consult the same retained gate, at most one claim with a given operation ID commits. Since a provider effect is attempted only after a successful claim, at most one **gated attempt** occurs for that ID. This does not establish at most one actual external effect if the provider has another route or duplicates effects within one attempt. Liveness fails if a process dies after claim commit and before effect. The code has not been shown to refine a checked formal model. A next experiment must bind a provider-enforced claim to signed authorization identity and run the provider and authority under separately administered credentials, including crashes and rollback of each independent domain.

Performance comparison, independent external verification, customer deployment, prior-art novelty analysis and IP counsel review: **NOT RUN** for this unit. SQLite unique claims and idempotency are established techniques. Do not infer novelty or patentability. The broader ĀML compiler, interface governance, browser and evidence surfaces remain separate and are not evaluated by this narrow experiment.
