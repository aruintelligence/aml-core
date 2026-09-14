# ĀML™ Field Receipt — Vancouver Security Hero Text CTA

Date: 2026-09-14
Evidence level: PROJECT-AUTHORED FIELD EVIDENCE
Public property: https://vancouversecurity.org/

## Element

Homepage hero secondary CTA: `Text Sales`.

The element repeated a texting path already available elsewhere in the interface. The site-specific phone and text routing were not changed.

## Declared labels

- attention_cost: 3
- restoration_value: 1
- label_source: project_authored_interface_review
- method: manual_source_and_rendered_interface_review

These values are declared/modelled policy inputs. They are not objective psychological, neurological, cognitive, wellbeing, or conversion measurements.

## Policy

`render_allowed = restoration_value >= attention_cost`

Evaluation: `1 >= 3` → false

Decision: **SUPPRESS**

## Before state

- Base44 checkpoint: `6aa815c75aaa604b651d1357`
- Base44 source commit: `c9c8186c0ec4ab4b8d4cca33db2207c950fc709f`
- Before element: hero contained both `Call Vancouver Sales` and `Text Sales` CTA buttons.

## Implemented after state

Only the hero `Text Sales` CTA was removed. The primary `Call Vancouver Sales` CTA remains. Texting remains available through other intentional interface surfaces, including the mobile control bar shown in the rendered after-state.

- Base44 checkpoint: `6aa8160ff0d4fd7bbd57b77e`
- Base44 source commit: `962882f0f63644ac584229a404160b873acbb68e`
- Vite production build: PASS
- Public after URL: https://vancouversecurity.org/

## Rendered after evidence

User supplied a mobile screenshot after publishing at approximately 08:43 local device time on 2026-09-14.

Screenshot SHA-256:

`48c18244520c429d7dd97c4588254afa1ec9d68d2c445c616861b677e37fe757`

Visible observations in the supplied screenshot:

- Vancouver Security / Security First Alarm branding is rendered.
- The sales-status ribbon remains.
- The header retains `Call (360) 690-0777`.
- The hero retains the primary `Call Vancouver Sales (360) 690-0777` CTA.
- The former secondary hero `Text Sales` CTA is absent.
- The fixed mobile controls still expose `Call`, `Text`, and `Get Help`.

The screenshot is evidence of the rendered interface state supplied by the project owner. It does not establish improved attention, usability, wellbeing, conversion rate, or commercial performance.

## Result

**SUPPRESS implemented and visually corroborated.**

This receipt demonstrates a narrow deterministic policy decision applied to a real customer-facing website with preserved before/after source checkpoints and a hashed rendered after-state. It is not independent validation or scientific proof of the declared labels.