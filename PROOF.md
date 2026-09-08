# ĀML Proof

**Status: SHIPPED**

If you only open one AML link, open this:

https://aruintelligence.github.io/aml-core/proof.html

ĀML is an interface firewall between AI/app intent and pixels.

The prototype rule used by this proof is:

```text
render_allowed = restoration_value >= attention_cost
```

## Reproduce a SUPPRESS decision

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=1

Expected: `SUPPRESS`.

## Reproduce an ALLOW decision

https://aruintelligence.github.io/aml-core/proof.html?attention=5&restoration=5

Expected: `ALLOW`.

## Prove replay locally

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
node demos/undeniable-proof/replay-proof.mjs
node scripts/check-flood-fixtures.js
```

CI requires deterministic replay and a balanced five-ALLOW / five-SUPPRESS fixture set.

## Inspect more

- View Meaning: https://aruintelligence.github.io/aml-core/view-meaning.html
- Embed proof: [docs/EMBED_PROOF.md](docs/EMBED_PROOF.md)
- Witness kit: [docs/WITNESS_KIT.md](docs/WITNESS_KIT.md)
- Machine-readable proof: [docs/proof-manifest.json](docs/proof-manifest.json)

The proof demonstrates deterministic software policy behavior for declared inputs. It does not claim that `attention_cost` or `restoration_value` objectively measure human cognition or wellbeing.

**Ask:** change one value, copy the exact proof URL, screenshot the result, and file what happened.
