# Ten browser-integration outreach notes

**Status: PITCH**

Each note asks for a concrete reproduction or integration. Do not mark any as sent unless actually sent.

## 1. Design-system maintainer

**Subject:** Can you test one `<aml-gate>` wrapper in a component library?

ĀML now has a zero-install custom element that uses the browser compiler to ALLOW or SUPPRESS wrapped HTML from declared attention/restoration inputs.

Live demo: https://aruintelligence.github.io/aml-core/aml-gate-demo.html

Would you try it around one disposable component and file what breaks?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 2. Vanilla-JS maintainer

**Subject:** Keep the HTML, add three AML data attributes

The new AML HTML bridge gates ordinary DOM with `data-aml-purpose`, `data-aml-attention-cost`, and `data-aml-restoration-value`.

Demo: https://aruintelligence.github.io/aml-core/dom-gate-demo.html

Would you try it on one static page and report the integration friction?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 3. React library maintainer

**Subject:** Does the AML web primitive compose cleanly with React?

ĀML already has a React adapter; I’ve now added a framework-neutral `<aml-gate>` custom element too.

Demo: https://aruintelligence.github.io/aml-core/aml-gate-demo.html

I want the smallest reproducible incompatibility, not praise.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 4. Web-components maintainer

**Subject:** Please critique this tiny AML custom element

Source: https://github.com/aruintelligence/aml-core/blob/main/docs/aml-gate.js

It observes declared purpose, attention cost, and restoration value, evaluates through the browser AML compiler, then emits an `aml-decision` event.

What would stop this from being a responsible web component?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 5. Browser-extension developer

**Subject:** Shareable AML proof states now have stable URLs

Proof states can now encode language, purpose, attention cost, and restoration value in the URL.

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1

Could a browser tool use this as a useful handoff target? I’d value a concrete critique.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 6. Static-site generator maintainer

**Subject:** Can an AML proof card live in generated docs?

Embeddable card:
https://aruintelligence.github.io/aml-core/proof-card.html?attention=5&restoration=1

README-safe badge:
https://aruintelligence.github.io/aml-core/proof-badge.svg

Would you test one link/embed path in generated docs?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 7. Localization engineer

**Subject:** Please break the eight-language AML proof

The live proof now carries `lang` in the URL and switches Arabic to RTL.

https://aruintelligence.github.io/aml-core/proof.html?lang=ar&attention=5&restoration=1

I want translation, layout, and directionality bugs filed publicly.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 8. Accessibility engineer

**Subject:** Audit the live AML proof before we call localization finished

The proof is mobile-responsive, keyboard-native HTML, and now multilingual, but that is not the same as an independent accessibility review.

https://aruintelligence.github.io/aml-core/proof.html

Please file specific failures rather than giving a general score.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 9. AI coding-agent developer

**Subject:** AML now publishes machine-discoverable proof surfaces

Reference discovery document:
https://aruintelligence.github.io/aml-core/.well-known/aml.json

Proof manifest:
https://aruintelligence.github.io/aml-core/proof-manifest.json

Could your tooling discover and reproduce one state without scraping prose?

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.

## 10. Open-source project maintainer

**Subject:** Put one AML proof link in a third-party README

Challenge:
https://github.com/aruintelligence/aml-core/issues/9

The acceptance bar is intentionally small: an independently maintained repository links to a reproducible AML proof state and accurately describes the observed result.

No certification claim is required.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
