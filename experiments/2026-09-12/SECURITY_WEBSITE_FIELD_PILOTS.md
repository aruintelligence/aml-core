# ĀML Security Website Field Pilots — 2026-09-12

Status: ACTIVE / PROJECT-AUTHORED FIELD EXPERIMENTS

ĀRU Intelligence is applying the ĀML research prototype to real customer-facing Security First Alarm web properties. These are project-authored field experiments on real production-oriented websites, with pre-change checkpoints preserved before interface changes.

## Current experiment

The network-wide pilot examines repeated high-salience interface elements, including sales/contact calls to action across ribbons, navigation, hero sections, page bodies, and mobile docks.

Each site's contact information is intentionally site-specific and must remain unchanged. The experiment evaluates presentation and repetition, not replacement of phone numbers, SMS routing, or email addresses.

Prototype policy: `render_allowed = restoration_value >= attention_cost`

Attention/restoration values are declared or modeled policy inputs. They are not objective measurements of cognition, psychology, neurological state, wellbeing, morality, or clinical outcome.

## Preserved pre-pilot evidence

| Property | Base44 checkpoint | Source commit |
|---|---|---|
| Security First Alarm Portland | `6aa5e639d7fa72652bd096b7` | `6b903756b6c8fb44ef9fa7845b68235b62193d1b` |
| PDX Fire Alarms | `6aa5e63ff2d1143d0dd5e05b` | `671c0b40c9736fd909d80f2872686a2ca4204bc2` |
| PDX Surveillance | `6aa5e6468e445d8df8a55c80` | `cdf1a44d889190b62c6656b77f776d4f172ecd39` |
| Portland Home Security | `6aa5e64b3affece0c34c969e` | `c3612b1b735871d192ecf0dc246b56a0a9039f91` |
| Vancouver Security | `6aa5e652f1d3871b3d0b749c` | `26b4fb00d7d011f4dbe242358addc585709e1b22` |
| Security First Alarm | `6aa5e658bf81b5ee1d7731dc` | `c7e28764878186a5780de23c73438e2dde39d60d` |
| Security First Alarm Sales | `6aa5e65d726855933055877f` | `7c2775d50ca20964ba5ce9d508e6490f0b538ac2` |
| Security First Alarm Service | `6aa5e664d0e21c24894c2acf` | `4e3e84a26a4819bd88b769e7852cf3babb429908` |

## Evidence protocol

For each site: preserve identity and before state; identify the exact UI element; preserve label provenance; record declared policy inputs and ALLOW/SUPPRESS result; preserve after state after publication; and publish reproducible evidence without describing project-authored work as independent validation.

Initial source inspection found repeated contact surfaces on Portland Home Security, PDX Fire Alarms, PDX Surveillance, Vancouver Security, and Security First Alarm. These are source-inspection observations, not measured claims about user psychology or conversion performance.

These pilots are project-authored field evidence. They are not independent reproduction, third-party certification, scientific validation, or proof of improved commercial conversion.

Next: complete element-level provenance and policy decisions, publish the resulting site changes, and add before/after artifacts and decision receipts here.
