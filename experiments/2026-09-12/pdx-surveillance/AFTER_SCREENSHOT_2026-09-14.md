# PDX Surveillance — rendered AFTER screenshot evidence

Date observed: 2026-09-14
Public property: https://pdxsurveillance.com/
Evidence class: project-authored / owner-supplied rendered screenshot

## Screenshot integrity

- Original uploaded image filename: `IMG_3780.jpeg`
- Byte length: `240744`
- SHA-256: `d11c3a8e4a71a7e4535a56129a367651eb99986ad2af6eeb9baba63cbb58324d`
- Capture context visible in screenshot: mobile Safari on iPhone, 8:29 local device time

The image itself was supplied directly by the project owner after publishing the Base44 change. The repository record preserves the cryptographic hash and visual interpretation of that rendered artifact. This record does not claim an independent third-party capture.

## What the rendered AFTER state shows

The screenshot confirms that the inline duplicate hero contact line targeted by the ĀML pilot is no longer present beneath the hero actions.

Visible contact paths intentionally remain:

- top navigation: `Call Sales`
- hero primary CTA: `Request Site Walk / Estimate`
- hero secondary CTA: `Text Sales (971) 458-1814`
- fixed mobile dock: `Call Sales`, `Text Sales`, `Estimate`

This is consistent with the experiment decision: suppress the immediate duplicate contact line while preserving site-specific contact routing and persistent user-control paths.

## Experiment linkage

- Before Base44 checkpoint: `6aa5e6468e445d8df8a55c80`
- Before source commit: `cdf1a44d889190b62c6656b77f776d4f172ecd39`
- After Base44 checkpoint: `6aa81171fb4e430c1b83e936`
- After source commit: `87d9aa1d6218163037abf96227d1cd6cbdbc3b8c`
- Declared attention cost: `4`
- Declared restoration value: `1`
- Policy: `restoration_value >= attention_cost`
- Decision: `SUPPRESS`
- Public after URL: https://pdxsurveillance.com/

## Boundary

The screenshot demonstrates the rendered post-change interface state. It does not prove improved conversion, reduced cognitive load, psychological benefit, or objective attention effects. The attention/restoration values remain declared/model-supplied policy inputs unless separately validated.
