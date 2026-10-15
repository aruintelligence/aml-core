// Compiled from a clean consumer install against the published package types.
import {
  AML_AGENT_UI_ENVELOPE,
  AML_GOVERNANCE_STREAM_FINALIZE,
  AML_GOVERNANCE_STREAM_NODE,
  AML_GOVERNANCE_STREAM_OPEN,
  compileSource,
  applyLockedHttpDecision,
  createAmlHttpServer,
  createAgentUiGateway,
  createDeploymentFirewall,
  createGovernanceStreamGateway,
  createGovernanceStreamSession,
  createInterfaceFirewall,
  evaluateAgentUI,
  evaluateLockedHttpAndRender,
  executeAccountableIntent,
  formatMeaningReport,
  generateAMLFromIntent,
  policyDiff,
  semanticDiff,
  signExecutionReceipt,
  simulatePolicies,
  verifyExecutionReceipt,
  verifySignedExecutionReceipt,
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
  max_batch_items: 100,
  max_inflight_requests: 100,
  auth_timeout_ms: 2000,
  request_auth: { bearer_token: "0123456789abcdef0123456789abcdef" },
  locked_policy: { profile: "human_first", resolve_context_timeout_ms: 2000, resolve_context: async (req, { signal }) => ({
    cancelled: signal.aborted,
    session: req.headers["x-session-id"]
  }) }
});
server.listen(0, "127.0.0.1");
server.close();
createAgentUiGateway({ locked_policy: { profile: "calm_default" }, auth_timeout_ms: 2000, max_body_bytes: 1024, max_components: 256, max_inflight_requests: 10 });
createGovernanceStreamGateway({ auth_timeout_ms: 2000, max_line_bytes: 1024, max_stream_bytes: 4096, max_messages: 10, max_inflight_requests: 10 });
createAmlHttpServer({ request_auth: async (_req, { signal }) => !signal.aborted });

// Keep expected type errors in the compiler's view without executing invalid
// calls when newer Node versions discover this .mts fixture under --test.
if (false) {
  const fingerprints: string[] = ["a".repeat(64)];
  evaluateLockedHttpAndRender({ url: "https://example.test/v1/deployment/evaluate", token: "secret",
    intent, profile: "human_first", context: {}, trustedReceiptFingerprints: fingerprints,
    render: async (html) => { void html; }, timeoutMs: 2000 }).then(result => {
    const status: "blocked" | "rendered" | "unknown" = result.status;
    void status;
  });
  applyLockedHttpDecision({ httpStatus: 503, body: null, intent, profile: "human_first",
    context: {}, trustedReceiptFingerprints: fingerprints, requestNonce: "b".repeat(64),
    render: () => {} });
  const signed = signExecutionReceipt(receipt, "private key PEM", { signer: "consumer" });
  const fingerprint: string = signed.signature.public_key_sha256;
  const attributionBound: boolean = verifySignedExecutionReceipt(signed).attribution_bound;
  createAmlHttpServer({ locked_policy: { profile: "human_first" }, receipt_signing: {
    private_key_pem: "private key PEM", signer: "consumer"
  } });
  void [fingerprint, attributionBound];
  // @ts-expect-error the runtime session exposes accept(), never handle().
  session.handle({ protocol: AML_GOVERNANCE_STREAM_FINALIZE });
  // @ts-expect-error a caller cannot select an unknown deployment mode.
  createAmlHttpServer({ locked_policy: { mode: "permissive" } });
  // @ts-expect-error bearer tokens are strings.
  createAmlHttpServer({ request_auth: { bearer_token: 123 } });
  // @ts-expect-error callback deadlines are numeric milliseconds.
  createAmlHttpServer({ auth_timeout_ms: "slow" });
  // @ts-expect-error concurrency ceilings are numeric.
  createAmlHttpServer({ max_inflight_requests: "unlimited" });
  // @ts-expect-error context deadlines are numeric milliseconds.
  createAmlHttpServer({ locked_policy: { resolve_context_timeout_ms: "slow" } });
  // @ts-expect-error a firewall run cannot request a made-up timestamp type.
  firewall.enforce(intent, { timestamp: 123 });
  // @ts-expect-error policy comparison requires both the left and right targets.
  policyDiff(source, "calm_default");
  // @ts-expect-error a simulation needs a list of policies, not one string.
  simulatePolicies(source, "restorative_v1");
}

void [html, receiptHash, verified, decision, renderable, finalized, allowedCount, provenanceValid,
  meaningLine, suppressed, additions, ambiguous, addedIdentifier, changedDecisions, simulatedRuns];
