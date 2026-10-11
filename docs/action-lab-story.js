// Presentation mapping for the local Action Boundary Lab. It uses the plan
// and rehearsal result; it does not make a second policy or dispatch decision.
export function actionPathStory(proposal, plan, approvedDigest, outcome) {
  const digest = plan?.proposal_sha256;
  const match = Boolean(digest && approvedDigest && digest === approvedDigest);
  const stale = Boolean(approvedDigest && !match);
  const readable = value => String(value || "unknown").replaceAll("_", " ");
  const proposalCard = proposal ? {
    value: proposal.tool,
    detail: `${proposal.effect.toUpperCase()} · ${proposal.resource}`,
    tone: "proposal"
  } : { value: "INVALID INPUT", detail: "Correct the proposed action fields.", tone: "blocked" };
  const policyCard = plan?.decision === "allow" ?
    { value: "ALLOW", detail: "Exact host rule · approval not required", tone: "allowed" } :
    plan?.decision === "requires_approval" ?
      { value: "APPROVAL REQUIRED", detail: "One exact host rule matches", tone: "awaiting" } :
      { value: "DENY", detail: `Host rule: ${readable(plan?.reason)}`, tone: "blocked" };
  const approvalCard = stale ?
    { value: "STALE", detail: "Prior simulated digest no longer matches", tone: "blocked" } :
    match ?
      { value: "DIGEST MATCH", detail: `Simulated approval · ${digest.slice(0, 12)}…`, tone: "allowed" } :
      plan?.decision === "allow" ?
        { value: "NOT NEEDED", detail: "This host rule allows the read", tone: "allowed" } :
        plan?.decision === "deny" ?
          { value: "NOT REACHED", detail: "Denied before approval", tone: "muted" } :
          { value: "AWAITING", detail: "No simulated approval recorded", tone: "awaiting" };
  const receiptCard = !outcome ?
    { value: "NOT ATTEMPTED", detail: "Rehearse dispatch to see an outcome", tone: "muted" } :
    outcome.outcome === "would_dispatch" ?
      { value: "WOULD DISPATCH", detail: "Simulation only · no tool ran", tone: "allowed" } :
      outcome.outcome === "unknown" ?
        { value: "UNKNOWN", detail: "A callback error cannot prove delivery", tone: "awaiting" } :
        { value: "BLOCKED", detail: `Reason: ${readable(outcome.reason)}`, tone: "blocked" };
  return { proposal: proposalCard, policy: policyCard,
    approval: approvalCard, receipt: receiptCard };
}
