# Action-boundary threat model v2

Scope: host-owned action authorization for one proposed tool action. The model, tool output, MCP descriptions and proposal object are untrusted. The host policy, approver authentication, target resolver, grant/operation store and tool callback are trusted **only if the host protects and routes them correctly**. SHA-256 binds canonical bytes; it does not establish approver identity or actual delivery.

## Assets and entry points

Assets are human authority, provider credentials, target/resource identity, payload integrity, one-use grants, revocation state, audit evidence and private content. Entry points include model proposals, tool metadata/results, JavaScript objects passed into canonicalization, approval responses, persisted grant files, provider responses and external verification inputs.

| Threat | Required condition | Expected control | Evidence / gap |
| --- | --- | --- | --- |
| Tool/destination/payload substitution | Untrusted action changes after approval | Frozen canonical proposal and host-derived target match | `boundary.mjs`, `target-boundary.mjs`, vectors and mutation tests; target resolver accuracy remains host responsibility. |
| Approval spoofing | Untrusted actor supplies `{approved:true,digest}` | Host authenticator plus durable grant issuer | Digest comparison exists; human identity is outside the reference. |
| Replay / partial storage loss | Spent marker lost but grant retained | Fail-closed store initialization and atomic claim | A-01 reproduced and fixed in the simple file pilot; whole-store rollback remains. |
| Host-clock rollback after expiry | Host clock moves backward after an issued grant expires | Durable spent marker on observed expiry; trusted time anchor for unobserved expiry | A-10 reproduced: an expired unclaimed grant revived at an earlier clock time. Pilot now spends it when expiry is observed. Rollback before any observation remains open. |
| Concurrent cold initialization | Two issuers open a fresh, empty grant directory together | Single initializer or transactional initialization | A-11: at least one issue rejected in each of 25 local trials; fail-closed availability gap. No multi-process initialization guarantee. |
| Policy revocation race | Policy changes during async approval/claim | Epoch-aware transactional handoff | Multiple bounded pilots exist; no production multi-host implementation. |
| Prototype/array-method confusion | Untrusted JS object or same-process prototype pollution | Canonical copy free of inherited serialization hooks | A-02 regression in Node/browser; host runtime compromise beyond this class remains. |
| Receipt tampering/key substitution | Verifier trusts unpinned claims or attacker-controlled key | Pinned trust root, signed evidence and append-only anchor | No universal trust root or external auditor is supplied by a local digest. |
| Provider uncertainty | Timeout after request may follow effect | Unknown state, idempotency and reconciliation | Local ledger models unknown; provider acceptance/completion unproven. |
| Bypass / malicious tool metadata | Another path calls provider directly | Host mediation of every effectful route | MCP tool descriptions cannot authorize; exhaustive host inventory is required. |
| Resource exhaustion / evidence leakage | Deep/cyclic/large inputs or sensitive logs | Bound size, depth/time, redaction and retention | Node/browser canonicalizers now reject cycles explicitly, and the guarded tool blocks them; deeply nested, proxy-driven, large input and logging review remain pending. |

Adversarial tests use isolated project-owned local files and callbacks. They do not attack third-party systems. A process with the host's OS identity, a malicious host, a compromised trusted store, or a dishonest provider is outside the narrow reference guarantee. The model should be revisited for each integration and deployment architecture.
