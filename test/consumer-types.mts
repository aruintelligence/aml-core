// Compiled from a clean consumer install against the published package types.
import {
  AML_AGENT_UI_ENVELOPE,
  AML_GOVERNANCE_STREAM_FINALIZE,
  AML_GOVERNANCE_STREAM_NODE,
  AML_GOVERNANCE_STREAM_OPEN,
  compileSource,
  createAmlHttpServer,
  createAgentUiGateway,
  createDeploymentFirewall,
  createGovernanceStreamGateway,
  createGovernanceStreamSession,
  createInterfaceFirewall,
  evaluateAgentUI,
  executeAccountableIntent,
  formatMeaningReport,
  generateAMLFromIntent,
  policyDiff,
  semanticDiff,
  simulatePolicies,
  verifyExecutionReceipt,
  viewMeaning,
  type AmlIntent
} from "aml-core";

const intent: AmlIntent = {
  transmission: "type_consumer",
  nodes: [{ type: "message", identifier: "continue", properties: {
    purpose: "Let the person continue", attention_cost: 1, restoration_value: 3
  } }]
};

const compiled = compileSource('transmission "type_consumer" { message "continue" { purpose: "Continue" attention_cost: 1 restoration_value: 3 } }');
const html: string = compiled.html;
const receipt = executeAccountableIntent(intent, { profile: "calm_default", timestamp: "2030-01-01T00:00:00Z" });
const receiptHash: string = receipt.receipt_sha256;
const verified: boolean = verifyExecutionReceipt(receipt).verified;
const decision: boolean = createDeploymentFirewall({ mode: "enforce", failure_mode: "closed" })
  .evaluate(intent).effective_allowed;
const firewall = createInterfaceFirewall({ profile: "calm_default" });
const enforced = firewall.enforce(intent, { timestamp: "2030-01-01T00:00:00Z" });
const allowedCount: number = enforced.allowed_count;
const provenanceValid: unknown = firewall.inspect(intent).provenance_verification;
const meaning = viewMeaning(enforced.receipt);
const meaningLine: string = formatMeaningReport(meaning);
const suppressed: number = meaning.summary.suppressed;
const comparison = semanticDiff(generateAMLFromIntent(intent), generateAMLFromIntent(intent));
const additions: number = comparison.summary.added;
const ambiguous: boolean = comparison.identity_ambiguity_detected;
const addedIdentifier: string | null | undefined = comparison.added[0]?.identifier;
const source = generateAMLFromIntent(intent);
const policyComparison = policyDiff(source, "calm_default", "strict_attention", { context: {} });
const changedDecisions: number = policyComparison.changed_decisions;
const simulation = simulatePolicies(source, ["restorative_v1", "attention_conservative_v1"]);
const simulatedRuns: number = simulation.runs.length;

const ui = evaluateAgentUI({ protocol: AML_AGENT_UI_ENVELOPE, components: [{
  id: "continue", governance: { purpose: "Continue", attention_cost: 1, restoration_value: 3 }
}] }, { mode: "enforce" });
const renderable: number = ui.renderable_components.length;

const session = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, mode: "enforce" });
session.accept({ protocol: AML_GOVERNANCE_STREAM_NODE, node: intent.nodes![0]! });
session.accept({ protocol: AML_GOVERNANCE_STREAM_FINALIZE });
const finalized: boolean = session.finalized;

const server = createAmlHttpServer({
  request_auth: { bearer_token: "0123456789abcdef0123456789abcdef" },
  locked_policy: { profile: "human_first", resolve_context: async (req) => ({
    session: req.headers["x-session-id"]
  }) }
});
server.listen(0, "127.0.0.1");
server.close();
createAgentUiGateway({ locked_policy: { profile: "calm_default" }, max_body_bytes: 1024 });
createGovernanceStreamGateway({ max_line_bytes: 1024, max_stream_bytes: 4096, max_messages: 10 });

// @ts-expect-error the runtime session exposes accept(), never handle().
session.handle({ protocol: AML_GOVERNANCE_STREAM_FINALIZE });
// @ts-expect-error a caller cannot select an unknown deployment mode.
createAmlHttpServer({ locked_policy: { mode: "permissive" } });
// @ts-expect-error bearer tokens are strings.
createAmlHttpServer({ request_auth: { bearer_token: 123 } });
// @ts-expect-error a firewall run cannot request a made-up timestamp type.
firewall.enforce(intent, { timestamp: 123 });
// @ts-expect-error policy comparison requires both the left and right targets.
policyDiff(source, "calm_default");
// @ts-expect-error a simulation needs a list of policies, not one string.
simulatePolicies(source, "restorative_v1");

void [html, receiptHash, verified, decision, renderable, finalized, allowedCount, provenanceValid,
  meaningLine, suppressed, additions, ambiguous, addedIdentifier, changedDecisions, simulatedRuns];
