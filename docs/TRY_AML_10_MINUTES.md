# Try ĀML in under 10 minutes

**Status: SHIPPED newcomer path**

ĀML is an interface firewall between AI/app intent and pixels.

## 1. Open the playground

https://aruintelligence.github.io/aml-core/playground.html

## 2. Paste this

```aml
transmission "proof" {
  message "pressure" {
    purpose: "Create urgency"
    content: "Act now"
    attention_cost: 5
    restoration_value: 1
  }
}
```

## 3. Compile

The prototype rule is:

```text
render_allowed = restoration_value >= attention_cost
```

With `1 < 5`, the element should be suppressed.

## 4. Change one number

Change:

```text
restoration_value: 1
```

to:

```text
restoration_value: 6
```

Compile again. The same element should now be allowed under the prototype rule.

## 5. Reproduce locally

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
node demos/undeniable-proof/replay-proof.mjs
node scripts/check-flood-fixtures.js
```

The replay proof executes the same fixed intent twice and requires identical receipt, decision, and output hashes.

## 6. Inspect meaning

https://aruintelligence.github.io/aml-core/view-meaning.html

## 7. File your result

If you reproduce it, disagree with it, or break it, open a GitHub issue and include the exact input and observed decision.

ĀML is a working prototype, not a ratified global standard. Its attention/restoration values are model inputs, not objective measures of human cognition.
