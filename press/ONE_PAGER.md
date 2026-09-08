# ĀML — One Page

**Status: DRAFT**

## What it is

ĀML is a prototype **interface firewall** between AI/app intent and pixels.

It makes five things inspectable:

1. declared purpose;
2. attention cost;
3. restoration value;
4. policy decision;
5. receipt.

## Baseline prototype rule

```text
render_allowed = restoration_value >= attention_cost
```

## Why this exists

Generated UI can be produced faster than a human can manually inspect every variation. ĀML explores whether interface intent and policy decisions can become explicit, reproducible software artifacts instead of remaining only in design docs or screenshots.

## What exists today

- compiler and browser playground;
- View Meaning receipt inspection;
- semantic and policy diffs;
- Meaning Gate CI checks;
- React/JavaScript/HTTP adoption paths;
- conformance fixtures and public protocol documents;
- dark-pattern proof fixtures.

## Try it

Playground: https://aruintelligence.github.io/aml-core/playground.html

View Meaning: https://aruintelligence.github.io/aml-core/view-meaning.html

Repository: https://github.com/aruintelligence/aml-core

## What it does not claim

ĀML is not a ratified global standard. Its present attention/restoration values are not validated measurements of human cognition or wellbeing. A receipt does not prove that an AI's declared intent is truthful. Accessibility checks do not replace WCAG or assistive-technology testing.

## License

Covered code is MIT licensed. Official ĀML/ĀRU brand rights are separate.

## Ask

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
