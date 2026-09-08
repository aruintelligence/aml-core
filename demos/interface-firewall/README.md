# Flagship demo — AI Interface Firewall™

This demo shows why ĀML exists without requiring someone to understand the whole language first.

## The setup

`before.aml` is a low-cost pricing explanation.

`after.aml` changes the same interface into a more aggressive, higher-attention, personal-data-collecting interaction that also requires consent.

The source still looks like “an interface,” but the **meaning changed**.

## 1. See the semantic change

```bash
node bin/aml.js semantic-diff demos/interface-firewall/before.aml demos/interface-firewall/after.aml
```

This should surface meaning-bearing changes such as:

- changed purpose;
- higher attention cost;
- new personal-data collection;
- new consent requirement;
- higher cognitive load.

## 2. Hold the source constant and compare policy

```bash
node bin/aml.js policy-diff demos/interface-firewall/after.aml calm_default human_first demos/interface-firewall/context.json
```

The point is not that one policy is universally correct. The point is that policy choice becomes explicit, inspectable, and reproducible.

## 3. Run the PR Meaning Gate

```bash
node scripts/meaning-gate.js \
  demos/interface-firewall/before.aml \
  demos/interface-firewall/after.aml \
  calm_default \
  human_first \
  demos/interface-firewall/context.json
```

The gate is designed to flag high-risk semantic changes and ALLOW → SUPPRESS policy regressions before deployment.

## 4. View Meaning™

The web has View Source. ĀML adds a path toward **View Meaning**: purpose, policy, attention, restoration, consent/privacy declarations, rationale, and receipt integrity.

Browser inspector:

https://aruintelligence.github.io/aml-core/view-meaning.html

## Why this demo matters

A normal text diff can tell you that fields changed. ĀML can tell tooling that the **declared purpose of the interface changed, the attention demand increased, personal-data collection appeared, consent became relevant, and policy outcome may change**.

That is the mainstream wedge: not replacing HTML, but adding an accountability layer in front of AI-generated or dynamically generated UI.

## Evidence boundary

The values in this fixture are declared model inputs for a reproducible software demonstration. They are not validated measurements of a person’s cognition, wellbeing, or harm.