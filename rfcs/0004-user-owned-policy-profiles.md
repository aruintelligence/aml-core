# RFC 0004 — User-Owned Policy Profiles

**Status:** Draft

## Summary

A user-owned policy profile is a portable declaration of interface constraints that an AML-aware system can apply before rendering. Examples include privacy consent requirements, reduced-motion preferences, cognitive-load limits, and cumulative attention budgets.

## Motivation

Today, users repeatedly configure similar preferences across unrelated products. AML can provide an interoperability layer where policy travels with the person rather than remaining trapped inside each application.

## Proposed principles

1. **User authority:** applications may add stricter organizational rules but must not silently weaken user-owned constraints.
2. **Minimization:** a profile should expose only the fields required for the current decision.
3. **Revocability:** consent and delegated permissions must be revocable and time-scoped where appropriate.
4. **Inspectable precedence:** conflicts between user and organization policies must be visible in the policy record.
5. **Portability:** the profile format should not depend on one UI framework or vendor.
6. **No hidden code:** portable policy packs should remain data-only unless an explicit, sandboxed extension mechanism is standardized later.

## Open questions

- selective disclosure of profile fields;
- delegated authority for guardians, institutions, or accessibility services;
- policy precedence across jurisdictions and organizations;
- signed profile issuers and trust chains;
- replay prevention and expiry semantics.

## Security/privacy

A policy passport can itself become sensitive personal data. Implementations must avoid centralizing or broadcasting the full profile when only one scoped constraint is needed.

## Compatibility

This RFC is intentionally draft. Existing built-in profiles are implementation features, not yet a stable portable-profile wire standard.