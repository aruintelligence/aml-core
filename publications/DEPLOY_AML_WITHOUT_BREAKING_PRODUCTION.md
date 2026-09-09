# Deploy ĀML Without Breaking Production

**Status: DRAFT adoption brief grounded in SHIPPED rollout controls**

The safest way to evaluate an interface firewall is not to flip it on everywhere at once.

ĀML now ships prototype rollout controls for a staged path:

```text
observe → compare → measure → enforce
```

## 1. Shadow first

`createDeploymentFirewall({ mode: "shadow" })` evaluates the AML policy decision while leaving the effective render decision allowed.

This lets a team ask:

- What would AML suppress?
- How often would it disagree with current behavior?
- Are evaluation errors occurring?
- Which interface patterns cause disagreement?

Shadow mode is observation, not proof of readiness.

## 2. Compare policy changes before switching

`evaluatePolicyCanary()` evaluates the same interface intent under a baseline profile and a candidate profile.

It reports:

- total decisions;
- changed decisions;
- candidate new suppressions;
- candidate new allows;
- the exact before/after decisions and receipt hashes.

It does **not** declare either policy morally correct.

## 3. Measure the rollout mechanically

`createRolloutMonitor()` aggregates local deployment-firewall results into rates such as:

- AML suppression rate;
- evaluation error rate;
- shadow rate;
- effective suppression count.

`evaluateRolloutCriteria()` can compare those observed values against thresholds supplied by the operator.

A passing result means only that those supplied numerical thresholds were met. It does not prove production readiness, safety, compliance, human benefit, or policy quality.

## 4. Enforce only after the team understands the behavior

Switching to `mode: "enforce"` allows the AML policy outcome to affect effective rendering.

The prototype also makes failure behavior explicit:

```text
failure_mode = open | closed
```

That decision belongs to the operator and should be made deliberately for the application context.

## Run the reference rollout

```bash
node examples/deployment-rollout.mjs
```

The example exercises:

1. an ALLOW case in shadow mode;
2. a SUPPRESS case in shadow mode;
3. a baseline/candidate policy canary;
4. an enforced suppress decision;
5. receipt hashes and rollout summary output.

## Evidence

- `runtime/deploymentFirewall.js`
- `runtime/policyCanary.js`
- `runtime/rolloutMonitor.js`
- `runtime/rolloutCriteria.js`
- `schema/deployment-firewall-result.schema.json`
- `schema/policy-canary-result.schema.json`
- `schema/rollout-monitor-summary.schema.json`
- `schema/rollout-criteria-result.schema.json`
- `examples/deployment-rollout.mjs`

This is a research-prototype rollout path, not a claim that ĀML is production-certified or already deployed by enterprises.
