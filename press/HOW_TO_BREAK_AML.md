# How to Break ĀML

**Status: DRAFT public challenge**

Do not praise ĀML. Try to break it.

## Challenge 1 — Semantic ambiguity

Find two AML sources that humans would interpret differently but the semantic diff treats as equivalent.

## Challenge 2 — Policy contradiction

Construct a policy/profile combination where the final decision hides meaningful dissent.

## Challenge 3 — Receipt mutation

Change one meaningful field without invalidating the integrity checks.

## Challenge 4 — Replay

Reuse a wire message or authorization after it should have expired or been rejected.

## Challenge 5 — Revocation

Show a path where a revoked authority is still treated as active.

## Challenge 6 — Accessibility abstraction

Find a UI that passes AML's declarative accessibility checks but obviously fails a real user with assistive technology.

## Challenge 7 — Misleading declared intent

Demonstrate how a malicious generator can truthfully satisfy the syntax while lying about its purpose. Then propose the smallest useful mitigation.

## Challenge 8 — Independent implementation

Implement one public fixture without importing `aml-core`. If your result disagrees, file the smallest ambiguous spec point.

## Rules

- use public code and fixtures;
- publish exact reproduction steps;
- do not expose real secrets or private signing keys;
- report high-impact vulnerabilities responsibly under `SECURITY.md` before public exploitation details.

Repository: https://github.com/aruintelligence/aml-core

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
