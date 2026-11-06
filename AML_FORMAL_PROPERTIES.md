# Bounded authorization properties

`scripts/check-action-authorization-model.mjs` explores four combinations of two workers' approval-digest match/mismatch. Each worker can request, atomically consume, dispatch, be blocked, or crash after consumption; revocation can occur at any enabled step. The checker exhaustively visits the reachable finite states in this abstraction and asserts:

1. **Authorization binding (bounded):** a mismatched approval never reaches `consumed` or `executed`.
2. **One use (bounded):** at most one worker executes with a single issued grant.
3. **Revocation (bounded):** no later execution occurs once revocation becomes effective in the model.
4. **Crash (bounded):** an unknown/crashed claim remains spent and cannot be reissued in the model.

Assumptions: one operation and one grant, two workers, one issuer, an immutable proposal digest, an already authenticated approval bit, a host-owned tool route, atomic durable claim, an atomic effective revocation flag, serializable transition order, and a trustworthy guard at dispatch. The script explores a *specification*, not the JavaScript filesystem implementation, a provider, the operating system, or a distributed system. It has no fairness, liveness, clock, network partition, or whole-store rollback model. A passing result is not a proof of production security.

Reproduce with `node scripts/check-action-authorization-model.mjs`. Runtime tests in `test/action-boundary-file-grant.test.js` separately check a real two-process local race and the A-01 loss regression. The existing `file-revocation-handoff.mjs` pilots need a separately linked refinement/implementation check before any formal-system claim.
