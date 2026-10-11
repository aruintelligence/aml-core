# Real-screen field study: contact continuity

[Open the visual inspector](https://aruintelligence.github.io/aml-core/field-contact-continuity.html) · [Current public page](https://portlandsbestsecurity.com/)

On October 11, 2026, a project-operated Chrome browser captured two desktop viewports of the live Portland home security page: the top at scrollY 0 and a scrolled state at scrollY 1872. Both original JPEGs are checked in, with hashes in [`observations.json`](observations.json). The source dimensions were 1348 × 926 pixels; the DOM viewport was 1363 × 936 at device pixel ratio 1. The browser inspected public anchor text, href, and bounding boxes without clicking the contact links. The page may change after this capture.

| Observed state | Visible call paths | Visible email paths |
|---|---:|---:|
| Top | Sales banner, navigation phone, fixed call dock | Fixed email dock |
| Scrolled | Navigation phone, fixed call dock | Fixed email dock |

The labels and their exact sources are separate in [`labels.json`](labels.json). The observed link destinations are preserved; the candidate does not substitute contact information. The design scores are project-authored hypotheses under `restoration_value >= attention_cost`, not visitor measurements or a customer approval. That prototype rule suppresses the repeated navigation number while keeping the sales banner and fixed call/email dock. The added contact-continuity guard requires at least one observed visible call and email path in **each captured state**.

The candidate passes with two call paths at the top and one after scrolling. A deliberately adverse variant also suppresses the fixed call dock. It still has the top banner at scrollY 0 but has **zero** observed call paths after scrolling, so the guard rejects it. That is the counterexample: evaluating only the first viewport can miss a lost task path later in the page.

```bash
node scripts/build-field-contact-continuity-report.mjs --check
node --test test/field-contact-continuity.test.js
```

The builder rehashes both original screenshots and compares the deterministic [published report](../../../docs/field-contact-continuity-report.json) against fresh results. The visual inspector overlays the exact source images; its outlines and suppressed state are illustrative, not a changed production site. The guard checks only the two observed desktop states and declared anchors. It does not establish mobile behavior, keyboard access, actual reachability of a phone or mailbox, accessibility or attention benefit, sales lift, independent validation, or a causal effect. A real deployment needs a site owner to review the label and proposed presentation, run device and assistive-technology checks, preserve the exact public destinations, then capture an actual after state.
