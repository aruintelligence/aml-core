# Timberline Greens × ĀML: mobile shortcut field experiment

**Date:** 2026-09-24  
**Property:** https://timberlinegreens.com  
**Public experiment:** https://timberlinegreens.com/research/aml-mobile-navigation  
**Project:** ĀRU Intelligence Inc. / Timberline Greens  
**Evidence class:** Project-authored implementation and deterministic compiler checks, not independent validation  
**Base44 app:** `6a95b8f27eada81f92ba8fbe`  
**Before checkpoint:** `6ab4d13f475644348364f050` / `a3d03aeabad1ceacdb3ac9ab40a89bb68925c0b8`  
**After checkpoint:** `6ab4d2ba5bcdbbc289dec065` / `cd0be673982323e321017a895ed99c2c09ab59c9`  
**ĀML repository baseline:** `aruintelligence/aml-core@1e2974548453cc077912d8e3dde9a0a40d07f24c`  
**Vendored browser compiler:** `docs/aml-browser.js`, GitHub blob `e4e64a00d20718c1b74d8e5dd9f9dd08b1b84865` (upstream MIT license)

## Research question

Can the public site use the actual ĀML browser compiler to remove a redundant current-page action from its fixed mobile shop bar while retaining other shopping routes, phone ordering and a safe fallback? This is a code and interface experiment. Whether it improves attention, accessibility, conversion or satisfaction has **not** been measured.

The selected element is the mobile bar in `src/components/shop/ShopComponents.jsx`. Before the change it displayed `Samples`, `Build kit`, and `Call to order` on every route. Thus the first action pointed to the current page on `/samples`, and the second pointed to the current page on `/ridge-kit`. The page content, global navigation, footer and phone contact remain accessible.

## Intervention

1. Pin and vendor the repository's dependency-free browser compiler into `src/lib/aml-browser.js`.
2. In `src/lib/amlStickyShopGate.js`, build one static transmission with three named engrams. The only varying input is the public pathname; all strings and scores are fixed in source. Call `compileSourceBrowser` and require all three decisions.
3. Render the mobile links according to `render_allowed`; use two columns when a duplicate is suppressed and three otherwise. Keep the phone action. Label the landmark `Mobile shopping shortcuts` and expose a source pin/fallback flag for inspection.
4. If compilation throws or yields an incomplete decision set, render all three shortcuts. This is fail-open for navigation, including the phone link.
5. Publish `/research/aml-mobile-navigation` with methods, outputs, provenance and limitations, and add it to the footer.

The policy is `restoration_value >= attention_cost`. Scores are **declared design assumptions**, not inferred from a visitor. The duplicate current-page action was assigned attention 3 / restoration 1. A useful action to another route was assigned 2 / 4; phone was assigned 1 / 5. Those numbers encode this site's limited editorial judgment so that the decision can be inspected and challenged. They do not scientifically quantify attention or restoration.

## Reproduction and immutable inputs

From the `aml-core` repository root:

```sh
node experiments/2026-09-24/verify-timberline.mjs
```

The [adapter snapshot](./timberline-sticky-gate.mjs) differs from the site's adapter only in the browser compiler import path. The [results JSON](./timberline-results.json) captures the actual site adapter's declared inputs and stable decisions, omitting compiler timestamps. The test asserts four route outcomes and two failure paths: an exception and an incomplete decision list. No form submission or customer data is required.

## Observed decisions

| Route | Samples | Build kit | Call | Mobile bar |
| --- | --- | --- | --- | --- |
| `/` | ALLOW (2/4) | ALLOW (2/4) | ALLOW (1/5) | Three actions |
| `/samples` | SUPPRESS (3/1) | ALLOW (2/4) | ALLOW (1/5) | Two actions |
| `/ridge-kit` | ALLOW (2/4) | SUPPRESS (3/1) | ALLOW (1/5) | Two actions |
| `/putting-greens` | ALLOW (2/4) | ALLOW (2/4) | ALLOW (1/5) | Three actions |
| Compiler exception or incomplete output | ALLOW | ALLOW | ALLOW | Three actions |

**Checks run in the Base44 sandbox:** four route assertions and two fail-open assertions passed; `npm run build` exited 0; changed-file ESLint exited 0 with one warning that `src/App.jsx` was ignored by the existing configuration. Vite emitted an outdated Browserslist dataset advisory. The source was inspected and the before checkpoint captured. The public site and experiment route were separately checked after code sync.

## Change control and limitations

The change is limited to the bottom bar at mobile breakpoints (`lg:hidden`), and suppression is limited to the two named current-page shortcuts. The decision is computed on route rendering with static source and no visitor-derived data. The public experiment page and its footer link do not require sign-in. A source pin protects provenance, but future upstream changes require explicit review rather than silent updates.

No independent accessibility audit, screen reader study, mobile-device matrix, traffic experiment, conversion analysis, or longitudinal outcome measurement was performed. The code checks demonstrate the policy output and fail-open behavior. They do not show that fewer shortcuts benefit customers. A follow-up should record mobile keyboard/focus and assistive-technology behavior, test route transitions on real devices, and pre-register privacy-preserving outcome metrics before claiming impact. Rollback is available from the before checkpoint above.
