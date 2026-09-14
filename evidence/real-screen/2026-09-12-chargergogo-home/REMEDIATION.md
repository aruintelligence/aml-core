# Shipped remediation result

The AML pilot led to an actual production change on `https://chargergogoplacements.com/`.

| Element | Before | Product action | After |
|---|---|---|---|
| Sales-hours announcement bar | SUPPRESS | Removed from the sticky header; sales hours remain available in lower-pressure contact context | Not rendered |
| Bailment warning bar | SUPPRESS | Disclosure retained, wording softened to “Venue note,” height reduced, uppercase removed, contrast reduced | ALLOW |

The before result was not blindly applied. Removing the redundant sales strip was appropriate; removing the bailment disclosure was not. The shipped change reduced its attention cost while preserving its risk-disclosure purpose.

Both before and after scores are project-directed reviewer judgments rather than objective measurements or independent validation. The evidence demonstrates a deterministic policy-and-remediation workflow, not universal correctness.
