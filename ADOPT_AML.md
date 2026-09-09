# Adopt ĀML™

ĀML™ — ĀRU Meaning Language™ is a working research prototype for accountable AI interfaces.

It is designed to sit between **machine intent** and **human-facing output** so teams can inspect, gate, sign, diff, authorize, and later verify what an AI-driven interface meant to do.

**You do not have to replace HTML, React, or your existing frontend.**

## Why developers are looking at this

AI-generated interfaces are getting easier to create. The missing layer is accountability:

- What was the interface trying to do?
- Which policy allowed or suppressed it?
- Which semantic state was actually released?
- Which key or release board authorized that state?
- Can another implementation verify the evidence without trusting the original runtime?

ĀML is an attempt to make those questions machine-verifiable.

## Try it in under 60 seconds

**Live one-click starter:**

https://aruintelligence.github.io/aml-core/quickstart.html

Or open the exact-state proof:

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1&lang=en

Change `restoration_value` from `1` to `5` and watch the deterministic decision move from **SUPPRESS** to **ALLOW**.

The prototype scores are declared/model inputs, not claimed objective measurements of cognition or wellbeing.

## Add accountability to existing HTML

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-dom-gate.js"></script>

<div
  data-aml-purpose="Create urgency"
  data-aml-attention-cost="5"
  data-aml-restoration-value="1">
  Offer expires soon.
</div>
```

Or wrap existing content:

```html
<script type="module" src="https://aruintelligence.github.io/aml-core/aml-gate.js"></script>

<aml-gate
  purpose="Create urgency"
  attention-cost="5"
  restoration-value="1">
  <button>Act now</button>
</aml-gate>
```

These browser bridges are intentionally narrow. They are adoption surfaces, not claims that three attributes replace the full ĀML policy, consent, privacy, accessibility, receipt, or trust stack.

## Use it from JavaScript

```js
import { compileSource } from "./compiler/compiler.js";

const result = compileSource(`
transmission "demo" {
  message "welcome" {
    purpose: "Explain the interface"
    attention_cost: 1
    restoration_value: 3
  }
}
`);

console.log(result.amt);
console.log(result.renderDecisions);
```

The canonical npm package identity is `aml-core`, but registry publication is still an explicit open distribution boundary. Until that is completed and independently verified, use the repository or the audited downloadable package artifact rather than pretending `npm install aml-core` is already canonical.

## What makes ĀML different

ĀML is not trying to be another visual component library. Its current architecture includes:

- Abstract Meaning Tree generation;
- deterministic meaning fingerprints;
- project-level Meaning Manifests;
- signed semantic roots;
- append-only Meaning Lineage;
- signed Semantic Release Proofs;
- in-toto Statement v1 export with an ĀML-specific predicate;
- GitHub/Sigstore custom artifact attestations;
- externally pinned release-key trust policies;
- M-of-N Semantic Release Quorum;
- immutable Release Authorization Profiles;
- independent verifier challenge kits and PASS/FAIL/MIXED witness records.

The idea is simple:

> **HTML tells the browser what to display. ĀML tells the system why it deserves to be displayed.**

## Verify without trusting ĀML

Start here:

- [Independent verification guide](VERIFY.md)
- [External verifier challenge](https://github.com/aruintelligence/aml-core/issues/56)
- [External application integration challenge](https://github.com/aruintelligence/aml-core/issues/57)
- [Security challenge](https://github.com/aruintelligence/aml-core/issues/58)
- [External Verifier Challenge and downloadable kit instructions](publications/EXTERNAL_VERIFIER_CHALLENGE.md)

A result maintained by `aruintelligence/aml-core` does **not** count as an external witness. The external witness counter stays at zero until another maintainer or organization produces reproducible public evidence.

## Five concrete ways to adopt it

1. **Existing HTML** — add the DOM bridge or `<aml-gate>` around one risky interaction.
2. **React/app integration** — put ĀML between model-generated intent and rendering for one component flow.
3. **CI meaning lock** — fail a pull request when compiled meaning changes unexpectedly.
4. **Semantic release evidence** — produce and verify a Semantic Release Proof for a project state transition.
5. **Production authorization** — require GitHub/Sigstore identity, a pinned release key, M-of-N quorum, and one immutable Release Authorization Profile.

## Good first experiments

Try ĀML where the UI itself carries risk or persuasion:

- AI-generated checkout or upsell UI;
- financial or healthcare-facing AI interfaces;
- consent and privacy prompts;
- notification/attention systems;
- autonomous agent dashboards;
- admin or security-control interfaces;
- AI-generated marketing calls to action;
- interfaces whose behavior needs audit evidence after deployment.

## Search/discovery terms

If you found this while researching any of these, you are in the right repository:

`accountable AI` · `AI interface firewall` · `AI-generated UI governance` · `semantic release proof` · `semantic provenance` · `in-toto custom predicate` · `Sigstore AI attestation` · `React AI accountability` · `proof-carrying interface` · `meaning-native computing` · `AI policy engine` · `semantic diff` · `M-of-N release authorization` · `AI audit evidence`

## What ĀML does not claim

ĀML does not automatically determine factual truth, morality, legality, safety, human wellbeing, certification, standards approval, or institutional legitimacy. Cryptographic evidence proves integrity/key possession and configured authorization—not objective correctness.

## Start here next

- [Copy-and-run AI Interface Firewall starter](starters/ai-interface-firewall/)
- [ĀML in 5 minutes](publications/START_HERE.md)
- [ĀML in one page](publications/AML_IN_ONE_PAGE.md)
- [Why AI-generated UI needs a firewall](publications/WHY_AI_UI_NEEDS_A_FIREWALL.md)
- [Developer integration brief](publications/DEVELOPER_INTEGRATION_BRIEF.md)
- [10-minute reproduction](docs/TRY_AML_10_MINUTES.md)
- [30-minute enterprise pilot](pilots/enterprise-30min/)
- [Public reading room](PUBLICATIONS.md)

If you build against ĀML and it works, publish the evidence. If it breaks, publish that too. Both are useful.

— Daniel Jacob Read IV

Steward: ĀRU Intelligence Inc.™
