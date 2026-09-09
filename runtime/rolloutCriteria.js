// runtime/rolloutCriteria.js
// Mechanical comparison of an AML rollout summary against operator-supplied thresholds.
// Passing these criteria is not a claim of safety, correctness, ethics, or production readiness.

function finiteNumber(value, name) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${name} must be a finite number.`);
  }
  return value;
}

function ratioBound(value, name) {
  finiteNumber(value, name);
  if (value < 0 || value > 1) throw new Error(`${name} must be between 0 and 1.`);
  return value;
}

export function evaluateRolloutCriteria(summary, criteria) {
  if (!summary || summary.protocol !== 'ĀML Rollout Monitor Summary') {
    throw new Error('summary must be an ĀML Rollout Monitor Summary.');
  }
  if (!criteria || typeof criteria !== 'object' || Array.isArray(criteria)) {
    throw new Error('criteria must be an object supplied by the operator.');
  }

  const checks = [];

  if (criteria.min_evaluations !== undefined) {
    const expected = finiteNumber(criteria.min_evaluations, 'min_evaluations');
    checks.push({
      criterion: 'min_evaluations',
      expected,
      observed: summary.total,
      passed: summary.total >= expected
    });
  }

  if (criteria.max_evaluation_error_rate !== undefined) {
    const expected = ratioBound(criteria.max_evaluation_error_rate, 'max_evaluation_error_rate');
    checks.push({
      criterion: 'max_evaluation_error_rate',
      expected,
      observed: summary.evaluation_error_rate,
      passed: summary.evaluation_error_rate <= expected
    });
  }

  if (criteria.max_aml_suppression_rate !== undefined) {
    const expected = ratioBound(criteria.max_aml_suppression_rate, 'max_aml_suppression_rate');
    checks.push({
      criterion: 'max_aml_suppression_rate',
      expected,
      observed: summary.aml_suppression_rate,
      passed: summary.aml_suppression_rate <= expected
    });
  }

  if (criteria.min_shadow_rate !== undefined) {
    const expected = ratioBound(criteria.min_shadow_rate, 'min_shadow_rate');
    checks.push({
      criterion: 'min_shadow_rate',
      expected,
      observed: summary.shadow_rate,
      passed: summary.shadow_rate >= expected
    });
  }

  if (checks.length === 0) {
    throw new Error('At least one rollout criterion is required.');
  }

  return {
    protocol: 'ĀML Rollout Criteria Result',
    version: '1.0',
    criteria_met: checks.every(check => check.passed),
    checks,
    observed: {
      total: summary.total,
      aml_suppression_rate: summary.aml_suppression_rate,
      evaluation_error_rate: summary.evaluation_error_rate,
      shadow_rate: summary.shadow_rate
    },
    claim_boundary: 'Operator-supplied thresholds only; criteria_met does not prove safety, correctness, ethics, compliance, or production readiness.'
  };
}
