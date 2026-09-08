# ĀML Launch Thread — 12 Posts

**Status: DRAFT**

1. AI-generated interfaces can change faster than humans can review them. ĀML is a prototype interface firewall that makes declared purpose, policy inputs, render decisions, and receipts inspectable. https://github.com/aruintelligence/aml-core

2. The prototype baseline is intentionally simple: `render_allowed = restoration_value >= attention_cost`. Those values are model inputs, not scientifically validated measurements.

3. The point is not the equation. The point is making interface decisions explicit enough to inspect, reproduce, diff, and gate in CI.

4. A countdown pressure element can declare high attention cost and low restoration value. Under the baseline policy, it is suppressed. Ordinary purchase UI can remain.

5. Try it yourself: https://aruintelligence.github.io/aml-core/playground.html Change `restoration_value`, compile again, and inspect the decision.

6. Then inspect an execution receipt with View Meaning: https://aruintelligence.github.io/aml-core/view-meaning.html

7. ĀML does not replace HTML or React. The current prototype can sit in front of existing UI as an interface firewall.

8. Meaning Gate brings the same idea into CI: semantic changes and policy regressions can be reviewed before deployment.

9. The code is MIT licensed. Technical conformance and official ĀML/ĀRU branding are separate questions.

10. What ĀML does NOT claim: global-standard status, verified ethical correctness, GDPR compliance, or a scientific measurement of human attention.

11. What would make it stronger: independent reproductions, external implementations, adversarial review, accessibility testing, and real integrations.

12. Don’t take the pitch on faith. Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
