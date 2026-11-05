# Rendered After-State Evidence — Portland Home Security

## Experiment
Human/business-rule override of the ĀML prototype gate for the homepage sales-status ticker.

## Evidence source
User-supplied mobile screenshot captured after the Base44 version was published on 2026-09-14 at approximately 08:39 Pacific Time.

## Screenshot integrity
- Uploaded artifact: `IMG_3781.jpeg`
- Bytes: `245288`
- SHA-256: `bb83fbb5e114042810c9121af8dc6783b528894be07a03331eb3caa32fa14f56`

The binary screenshot is not asserted to be stored in this repository by this record. This document preserves its digest, provenance, and observed rendered state.

## Rendered observations
The screenshot visibly shows the retained blue sales-status ticker at the top of the mobile homepage with:

- `SALES OPEN NOW`
- `7 Days a Week · 7:00 AM–10:00 PM Pacific Time`
- `CALL OR TEXT (971) 458-1814`
- a separate local-time strip showing Portland, Oregon and Pacific Time

The screenshot also shows the Security First Alarm navigation/contact header, the residential-security hero imagery, and a lower persistent `CALL OR TEXT` action. This confirms that the element selected for the experiment remained rendered after publication.

## Decision chain
Declared prototype inputs:

```text
attention_cost = 4
restoration_value = 2
```

Prototype gate:

```text
render_allowed = restoration_value >= attention_cost
2 >= 4 -> false
GATE RESULT = SUPPRESS
```

Final governed disposition:

```text
RETAIN-BY-BUSINESS-RULE
```

Reason: the ticker carries distinct operational information—live sales availability and hours—in addition to contact routing. The business-rule review therefore overrides the simple prototype gate.

## Base44 evidence
- Before checkpoint: `6aa813b67e289e6e7f560d86`
- Before source commit: `7f890be3ac6402f651d79c0e42d5f635039fa3a3`
- After checkpoint: `6aa813d7c1e184d9c68e2a2d`
- After source commit: `e85e2d2d1dfc51e4ab49f687acebdc210f868159`
- Production build: PASS

## Evidence boundary
This is project-authored field evidence. The attention/restoration values are declared/modelled policy inputs, not objective cognitive, psychological, neurological, wellbeing, or conversion measurements. The screenshot demonstrates the rendered after-state; it does not by itself establish that retaining the ticker improved user outcomes or commercial performance.
