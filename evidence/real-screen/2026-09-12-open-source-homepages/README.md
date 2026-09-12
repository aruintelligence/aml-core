# Public open-source homepage cohort

This cohort applies the AML real-screen pilot to three public, unauthenticated,
developer-facing homepages captured on 2026-09-12: React, Vite, and MDN Web
Docs. The sites were selected because their website code or platform code has a
public repository and a documented contribution path, not because they agreed
to participate or endorsed AML.

## Collection boundary

- One ordinary page load per site in a cloud browser; no login, form submission,
  crawling, rate testing, access-control testing, or circumvention.
- The exact captured viewport was preserved outside Git and hashed. The evidence
  committed here contains capture hashes and a small semantic extraction, not a
  redistributable copy of each site's screenshot, assets, or rendered HTML.
- Element labels are project-directed operator judgments. They are neither
  objective attention/restoration measurements nor independent validation.
- The only decision rule is
  `render_allowed = restoration_value >= attention_cost`.
- A `SUPPRESS` result is a hypothesis for maintainer review or an experiment. It
  is not authorization to change a third-party site and may conflict with
  sponsorship, advertising, accessibility, legal, or product requirements that
  are not visible from the captured screen.

## Maintainer-facing use

The respectful outreach path is to link the receipt, identify the exact viewport
and element, disclose the label provenance, and ask whether a small controlled
experiment would be welcome. Do not mass-file issues, imply a security problem,
claim affiliation, or present the numeric judgments as user research.

| Site | Public project path | Result | Practical recommendation |
| --- | --- | --- | --- |
| React | `reactjs/react.dev` | 6 ALLOW, 0 SUPPRESS | No change proposed; use as a calm-screen control. |
| Vite | `vitejs/vite` | 6 ALLOW, 1 SUPPRESS | Test a less salient sponsor strip only with maintainer/sponsor approval. |
| MDN | `mdn/yari` | 6 ALLOW, 3 SUPPRESS | Do not remove revenue-bearing ads unilaterally; test reduced salience or a user preference with the team. |

No third-party issue or pull request was opened as part of this evidence run.

This is a conservative public-review boundary, not legal advice or a conclusion
that every downstream use is lawful in every jurisdiction.
