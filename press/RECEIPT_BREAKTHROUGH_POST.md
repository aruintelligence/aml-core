# A receipt is useful only if someone else can verify it

**Status: PITCH**

ĀML execution receipts are meant to make interface decisions inspectable after the fact.

The repository now proves something basic but important on every CI run: the same accountable intent, evaluated with the same fixed execution inputs, produces the same receipt hash, decision hash, output hash, and receipt object on replay.

Run it yourself:

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
node demos/undeniable-proof/replay-proof.mjs
```

The receipt does not prove that an AI's declared intent was truthful. It proves what the AML runtime evaluated and bound together for that execution.

That is a smaller claim, and a testable one.

Interactive proof:
https://aruintelligence.github.io/aml-core/proof.html

View Meaning:
https://aruintelligence.github.io/aml-core/view-meaning.html

**Ask:** mutate a receipt field, run verification, and file anything that still verifies when it should not.
