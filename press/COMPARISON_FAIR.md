# Fair Comparison: CSP vs Consent Banner vs ĀML

**Status: DRAFT**

| Question | CSP | Consent banner | ĀML prototype |
|---|---|---|---|
| Controls which network/script sources may load? | Yes | No | No |
| Captures user consent choices? | Not primarily | Yes | Can consume declared consent context |
| Evaluates declared purpose of a UI element? | No | Usually no | Yes |
| Carries attention/restoration metadata? | No | No | Yes |
| Can suppress an element based on a selected policy? | No | Sometimes indirectly | Yes |
| Produces an execution receipt? | No | Usually no | Yes |
| Replaces CSP? | — | No | No |
| Replaces a consent-management platform? | No | — | No |
| Proves legal compliance? | No | No | No |
| Primary value | Browser security policy | Consent capture/management | Inspectable interface-policy execution |

ĀML is complementary. It should not be marketed as a replacement for browser security headers, consent-management systems, accessibility testing, or legal compliance programs.

Try the prototype: https://aruintelligence.github.io/aml-core/playground.html

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
