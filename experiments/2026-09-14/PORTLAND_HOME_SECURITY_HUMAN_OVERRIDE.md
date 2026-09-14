# Portland Home Security — ĀML Human Override Field Experiment

## Result

**ĀML gate result:** SUPPRESS  
**Final disposition:** RETAIN-BY-BUSINESS-RULE

This experiment was created specifically to test the governance boundary that ĀML™ does not have absolute authority over a live business interface.

## Element

Top sales-status ticker on Portland Home Security. The element communicates whether sales is currently open, the current sales-hours context, and a direct call/text path.

## Declared labels

- attention_cost = 4
- restoration_value = 2
- label source = project-owner declared

Prototype policy:

```text
render_allowed = restoration_value >= attention_cost
```

Under the simple prototype gate, `2 >= 4` is false, so the gate result is **SUPPRESS**.

These values are declared prototype inputs. They are not objective measurements of cognition, psychology, neurological state, wellbeing, morality, or clinical outcome.

## Human/business review

The ticker was **not removed**. It carries distinct operational utility that is not equivalent to a generic repeated CTA:

- live Sales Open Now / Sales Hours state
- current sales-hours information
- Pacific-time operational context
- immediate contact path during the stated sales window

The project therefore records an explicit human/business override:

```text
FINAL DISPOSITION = RETAIN-BY-BUSINESS-RULE
```

Reason: `live-sales-availability-and-hours-provide-distinct-operational-utility`

## Before state

- Base44 checkpoint: `6aa813b67e289e6e7f560d86`
- Source commit: `7f890be3ac6402f651d79c0e42d5f635039fa3a3`

## After state

The visible UI is intentionally unchanged. ĀML provenance and override metadata were added to the retained element so the disagreement between the prototype gate and final business disposition is inspectable in source.

- Base44 checkpoint: `6aa813d7c1e184d9c68e2a2d`
- Source commit: `e85e2d2d1dfc51e4ab49f687acebdc210f868159`
- Production build: PASS

Metadata added to the element records:

- purpose
- declared attention cost
- declared restoration value
- gate result = SUPPRESS
- final disposition = RETAIN-BY-BUSINESS-RULE
- override reason

## Why this matters

A governance system that blindly executes every gate result would simply relocate authority from a human product owner to a policy engine. This experiment demonstrates the opposite design goal: the gate may surface a decision, while accountable humans can retain an element for a documented reason and preserve that override as evidence.

This is project-authored field evidence, not independent validation.

## Receipt

Machine-readable receipt: `PORTLAND_HOME_SECURITY_HUMAN_OVERRIDE.json`

Canonical receipt SHA-256:

`314568875bd433d9bf75f4686b43086b10b5b2581bfeb6268924234bcc7760d2`
