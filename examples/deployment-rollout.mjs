import {
  createDeploymentFirewall,
  createRolloutMonitor,
  evaluatePolicyCanary
} from '../index.js';

const timestamp = '2030-01-01T00:00:00.000Z';

const helpful = {
  transmission: 'rollout_demo',
  nodes: [{
    type: 'message',
    identifier: 'helpful',
    properties: {
      purpose: 'Explain the next step',
      content: 'Continue when ready',
      attention_cost: 1,
      restoration_value: 2
    }
  }]
};

const pressure = {
  transmission: 'rollout_demo',
  nodes: [{
    type: 'message',
    identifier: 'pressure',
    properties: {
      purpose: 'Create urgency',
      content: 'Act now',
      attention_cost: 5,
      restoration_value: 1
    }
  }]
};

const monitor = createRolloutMonitor({ max_records: 20 });
const shadow = createDeploymentFirewall({ mode: 'shadow', profile: 'calm_default' });

for (const intent of [helpful, pressure]) {
  const result = shadow.evaluate(intent, { timestamp });
  monitor.record(result, { label: intent.nodes[0].identifier, recorded_at: timestamp });
}

const canary = evaluatePolicyCanary(pressure, {
  baseline_profile: 'calm_default',
  candidate_profile: 'human_first',
  timestamp
});

const enforce = createDeploymentFirewall({ mode: 'enforce', profile: 'calm_default' });
const enforced = enforce.evaluate(pressure, { timestamp });

const output = {
  protocol: 'ĀML Deployment Rollout Demo',
  version: '1.0',
  shadow_summary: monitor.summary(),
  canary: {
    baseline_profile: canary.baseline_profile,
    candidate_profile: canary.candidate_profile,
    changed_decisions: canary.changed_decisions,
    candidate_new_suppressions: canary.candidate_new_suppressions,
    candidate_new_allows: canary.candidate_new_allows,
    baseline_receipt_sha256: canary.baseline.receipt_sha256,
    candidate_receipt_sha256: canary.candidate.receipt_sha256
  },
  enforced: {
    aml_allowed: enforced.aml_allowed,
    effective_allowed: enforced.effective_allowed,
    receipt_sha256: enforced.result.receipt.receipt_sha256
  }
};

console.log(JSON.stringify(output, null, 2));

if (output.shadow_summary.total !== 2) process.exit(1);
if (output.shadow_summary.would_suppress !== 1) process.exit(1);
if (output.enforced.aml_allowed !== false) process.exit(1);
if (output.enforced.effective_allowed !== false) process.exit(1);
