# Ten interface decisions, one rule

**Status: PITCH**

ĀML now has a public decision gallery with five ALLOW examples and five SUPPRESS examples.

Browse it:
https://aruintelligence.github.io/aml-core/gallery.html

Each card shows:

- a concrete interface pattern
- declared attention cost
- declared restoration value
- ALLOW or SUPPRESS
- a link that reopens the exact proof state

The point is not to claim that these values are objective measurements. The point is to make the software decision reproducible and inspectable.

Source fixtures:
https://github.com/aruintelligence/aml-core/tree/main/conformance/flood

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
