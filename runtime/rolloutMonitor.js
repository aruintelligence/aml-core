// runtime/rolloutMonitor.js
// Local rollout telemetry aggregator for deployment-firewall results.
// It does not transmit data and does not infer user outcomes.

function ratio(numerator, denominator) {
  return denominator === 0 ? 0 : numerator / denominator;
}

export function createRolloutMonitor(options = {}) {
  const maxRecords = options.max_records ?? 1000;
  if (!Number.isInteger(maxRecords) || maxRecords <= 0) {
    throw new Error("max_records must be a positive integer.");
  }

  const records = [];

  function record(result, metadata = {}) {
    if (!result || result.protocol !== "ĀML Deployment Firewall Result") {
      throw new Error("record expects an ĀML Deployment Firewall Result.");
    }
    if (records.length >= maxRecords) records.shift();
    records.push({
      recorded_at: metadata.recorded_at ?? new Date().toISOString(),
      label: metadata.label ?? null,
      transmission: metadata.transmission ?? result.result?.receipt?.intent?.transmission ?? null,
      profile: result.profile,
      mode: result.mode,
      failure_mode: result.failure_mode,
      aml_allowed: result.aml_allowed,
      effective_allowed: result.effective_allowed,
      would_suppress: result.would_suppress,
      evaluation_error: result.evaluation_error,
      receipt_sha256: result.result?.receipt?.receipt_sha256 ?? null
    });
    return records.length;
  }

  function summary() {
    const total = records.length;
    const errors = records.filter(item => item.evaluation_error).length;
    const amlAllowed = records.filter(item => item.aml_allowed === true).length;
    const amlSuppressed = records.filter(item => item.aml_allowed === false).length;
    const shadow = records.filter(item => item.mode === "shadow").length;
    const enforce = records.filter(item => item.mode === "enforce").length;
    const wouldSuppress = records.filter(item => item.would_suppress).length;
    const effectiveSuppressed = records.filter(item => item.effective_allowed === false).length;

    return {
      protocol: "ĀML Rollout Monitor Summary",
      version: "1.0",
      total,
      aml_allowed: amlAllowed,
      aml_suppressed: amlSuppressed,
      evaluation_errors: errors,
      shadow_evaluations: shadow,
      enforced_evaluations: enforce,
      would_suppress: wouldSuppress,
      effective_suppressed: effectiveSuppressed,
      aml_suppression_rate: ratio(amlSuppressed, total),
      evaluation_error_rate: ratio(errors, total),
      shadow_rate: ratio(shadow, total),
      records_retained: records.length,
      max_records: maxRecords
    };
  }

  return {
    protocol: "ĀML Rollout Monitor",
    version: "1.0",
    max_records: maxRecords,
    record,
    summary,
    records() {
      return structuredClone(records);
    },
    clear() {
      records.length = 0;
    }
  };
}
