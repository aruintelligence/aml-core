# ĀML Technical Due Diligence Checklist

**Status: DRAFT evaluation aid grounded in SHIPPED surfaces**

Before adopting AML beyond a prototype pilot, verify:

1. Parser/compiler behavior on your real inputs.
2. Policy behavior under explicit fixtures.
3. Deterministic replay where required.
4. Receipt integrity and mutation rejection.
5. Browser integration boundaries.
6. Performance under realistic load.
7. Accessibility implications of suppress/allow behavior.
8. Data-handling and privacy assumptions.
9. Independent verification against the immutable verifier contract snapshot.
10. Failure behavior when declarations are missing or malformed.
11. Upgrade/migration behavior across future contract snapshots.
12. Operational controls that AML does not provide, including authentication, authorization, TLS, secrets, rate limits, and production monitoring.

A successful checklist is evidence for your own deployment decision. It is not an ĀRU certification or legal/compliance guarantee.
