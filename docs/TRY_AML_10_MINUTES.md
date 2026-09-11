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

## 5. Reproduce locally with one command

```bash
git clone https://github.com/aruintelligence/aml-core.git
cd aml-core
npm install --ignore-scripts
npm run proof
```

`npm run proof` performs two checks:

1. replays the same fixed intent twice and requires identical receipt, decision, and output hashes;
2. runs the balanced ALLOW/SUPPRESS flood fixtures used to catch one-sided or silently permissive behavior.

A nonzero exit code is a failed reproduction and should be reported as such. Do not convert a failed run into a PASS because another project test succeeded.

For manual comparison, the command is equivalent to:

```bash
node demos/undeniable-proof/replay-proof.mjs
node scripts/check-flood-fixtures.js
```

## 6. Generate a publishable machine-readable report

```bash
npm run proof:report
```

This writes `aml-proof-report.json` in the current directory. The report includes:

- PASS / FAIL result;
- Node, platform, architecture, and OS release;
- deterministic replay hashes;
- balanced fixture counts;
- the canonical independent-verification issue;
- an explicit evidence-boundary statement.

You can also choose the output path directly:

```bash
node scripts/proof-report.mjs ./my-aml-proof-report.json
```

The generated file is intentionally self-describing so an outside tester can publish the exact artifact they observed instead of rewriting results by hand.

Important: a report generated inside this repository is still project-authored engineering evidence. It becomes independent external evidence only when an outside tester runs the command in their own environment and publishes their own reproducible result.

## 7. Inspect meaning

https://aruintelligence.github.io/aml-core/view-meaning.html

## 8. File your result

Use the canonical independent-verification issue:

https://github.com/aruintelligence/aml-core/issues/88

Report **PASS / FAIL / MIXED** and include the exact commit or release, environment, command, and observed output. Attach or link your `aml-proof-report.json` when useful. Negative results are useful.

ĀML is a working prototype, not a ratified global standard. Its attention/restoration values are declared or model-supplied inputs, not objective measures of human cognition or wellbeing.
