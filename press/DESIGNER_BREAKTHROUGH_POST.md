# Design systems need a layer between intent and pixels

**Status: PITCH**

A dark pattern is usually reviewed after it exists: in a mockup, screenshot, experiment, complaint, or policy audit.

ĀML is testing a different workflow: declare the purpose and interface-cost inputs before rendering, run them through a policy, and leave an inspectable result.

Try the smallest example:

SUPPRESS:
https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1

ALLOW:
https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=5

The prototype rule is visible:

`render_allowed = restoration_value >= attention_cost`

This is not a claim that design judgment can be reduced to two numbers. The point is that a UI decision can become explicit, reviewable, replayable, and testable instead of living only in a screenshot.

**Ask:** change the values until you disagree with the result. Copy that exact proof URL and file the disagreement. That is more useful than praise.
