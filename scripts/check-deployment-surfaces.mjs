import fs from 'node:fs';

const requiredFiles = [
  'runtime/decisionCache.js',
  'runtime/deploymentFirewall.js',
  'runtime/streamingInterfaceFirewall.js',
  'runtime/batchInterfaceFirewall.js',
  'runtime/policyCanary.js',
  'runtime/rolloutMonitor.js',
  'docs/aml-deployment-mode.js',
  'docs/deployment-mode-demo.html',
  'examples/deployment-rollout.mjs'
];

const failures = [];
for (const file of requiredFiles) {
  if (!fs.existsSync(file)) failures.push(`${file}: missing`);
}

function requireText(file, patterns) {
  if (!fs.existsSync(file)) return;
  const text = fs.readFileSync(file, 'utf8');
  for (const pattern of patterns) {
    if (!text.includes(pattern)) failures.push(`${file}: missing ${JSON.stringify(pattern)}`);
  }
}

requireText('runtime/deploymentFirewall.js', [
  'ĀML Deployment Firewall Result',
  'shadow',
  'failure_mode',
  'effective_allowed',
  'would_suppress'
]);
requireText('runtime/streamingInterfaceFirewall.js', [
  'ĀML Streaming Interface Firewall',
  'AML_STREAM_ALREADY_FINALIZED',
  'receipt_sha256'
]);
requireText('runtime/batchInterfaceFirewall.js', [
  'ĀML Batch Interface Result',
  'AML_BATCH_LIMIT_EXCEEDED'
]);
requireText('runtime/policyCanary.js', [
  'ĀML Policy Canary Result',
  'candidate_new_suppressions',
  'candidate_new_allows'
]);
requireText('runtime/rolloutMonitor.js', [
  'ĀML Rollout Monitor Summary',
  'aml_suppression_rate',
  'evaluation_error_rate'
]);
requireText('docs/aml-deployment-mode.js', [
  "['enforce', 'shadow']",
  "['open', 'closed']",
  'setAMLDeploymentMode',
  'setAMLFailureMode'
]);
requireText('docs/aml-live.js', [
  'effective_rendered',
  'effective_suppressed',
  'shadowed_suppressions'
]);
requireText('docs/aml.js', [
  'setDeploymentMode',
  'setFailureMode',
  'getDeploymentMode',
  'getFailureMode'
]);
requireText('server/httpServer.js', [
  '/v1/deployment/evaluate',
  'aml-http-deployment-evaluation/1'
]);
requireText('index.js', [
  'createDeploymentFirewall',
  'createStreamingInterfaceFirewall',
  'evaluateInterfaceBatch',
  'evaluatePolicyCanary',
  'createRolloutMonitor'
]);

const result = {
  protocol: 'aml-deployment-surface-check/1',
  verified: failures.length === 0,
  required_files: requiredFiles.length,
  failures
};

console.log(JSON.stringify(result, null, 2));
if (failures.length) process.exit(1);
