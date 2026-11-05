// Experimental in-memory execution-state reducer. The host supplies and
// authenticates evidence references; this module neither calls a provider nor
// proves that a reference describes a real external event.
const transitions = Object.freeze({
  proposed: ["approved", "blocked"],
  approved: ["grant_consumed", "blocked"],
  grant_consumed: ["request_initiated", "outcome_uncertain"],
  request_initiated: ["provider_accepted", "outcome_uncertain"],
  provider_accepted: ["completed", "outcome_uncertain"],
  completed: ["independently_confirmed", "outcome_uncertain"],
  outcome_uncertain: ["provider_accepted", "completed"],
  blocked: [],
  independently_confirmed: []
});

export function createProviderExecutionState({ operationId, proposalSha256 } = {}) {
  if (typeof operationId !== "string" || !operationId.trim() ||
      typeof proposalSha256 !== "string" || !/^[a-f0-9]{64}$/.test(proposalSha256)) {
    throw new TypeError("host operation ID and proposal digest required");
  }
  const entries = [];
  let state = "proposed";
  const snapshot = () => Object.freeze({ protocol: "aml-provider-execution-state/1",
    operation_id: operationId, proposal_sha256: proposalSha256, state,
    events: Object.freeze([...entries]) });
  return Object.freeze({
    record(next, evidenceRef) {
      if (!transitions[state].includes(next) ||
          typeof evidenceRef !== "string" || !evidenceRef.trim() || evidenceRef.length > 512) {
        throw new Error("invalid_execution_transition");
      }
      // A later event cannot rewrite an earlier event or its evidence label.
      entries.push(Object.freeze({ from: state, to: next, evidence_ref: evidenceRef }));
      state = next;
      return snapshot();
    },
    snapshot
  });
}
