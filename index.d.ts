export type AmlMode = "enforce" | "shadow";
export type AmlFailureMode = "closed" | "open";
export type AmlContext = Record<string, unknown>;

export interface AmlIntentNode {
  type: string;
  identifier?: string;
  properties?: Record<string, unknown>;
  children?: AmlIntentNode[];
}

export interface AmlIntent {
  transmission?: string;
  nodes?: AmlIntentNode[];
}

export interface RenderDecision {
  node_type: string;
  identifier?: string;
  purpose: string | null;
  policy_id: string;
  render_allowed: boolean;
  timestamp: string;
  [key: string]: unknown;
}

/** @deprecated Use RenderDecision or AgentUiDecision for the relevant API. */
export interface InterfaceGovernanceDecision {
  id?: string;
  render?: boolean;
  decision?: "ALLOW" | "SUPPRESS" | string;
  [key: string]: unknown;
}

export interface CompileResult {
  tokens: unknown[];
  ast: unknown;
  amt: unknown;
  renderDecisions: RenderDecision[];
  html: string;
}

export interface CompileFileResult extends CompileResult {
  input: string;
  output: string;
  buildManifest: unknown;
}

export interface CompileOptions {
  timestamp?: string;
  policy?: string | Record<string, unknown> | ((...args: unknown[]) => unknown);
  context?: AmlContext;
}

export interface ExecutionReceipt {
  protocol: "ĀML Accountable Execution Receipt";
  version: string;
  timestamp: string;
  profile: { id: string; description: string; policies: string[] };
  context: AmlContext;
  intent_sha256: string;
  aml_sha256: string;
  output_sha256: string;
  receipt_sha256: string;
  intent: AmlIntent;
  selected_render: {
    policy_id: string;
    allowed: number;
    suppressed: number;
    decisions: RenderDecision[];
    html: string;
  };
  [key: string]: unknown;
}

export interface ReceiptVerification {
  verified: boolean;
  receipt_hash_valid: boolean;
  bindings_valid: boolean;
  expected_sha256: string;
  receipt_sha256: string;
  [key: string]: unknown;
}

export interface InterfaceFirewallOptions {
  profile?: string;
  context?: AmlContext;
}

export interface InterfaceFirewallRunOptions extends InterfaceFirewallOptions {
  timestamp?: string;
  stream_id?: string;
}

export interface InterfaceInspection {
  profile: string;
  receipt: ExecutionReceipt;
  receipt_verification: ReceiptVerification;
  provenance: unknown;
  provenance_verification: unknown;
  accessibility: unknown;
}

export interface InterfaceEnforcement {
  allowed: boolean;
  denied_count: number;
  allowed_count: number;
  html: string;
  decisions: RenderDecision[];
  receipt: ExecutionReceipt;
  report: InterfaceInspection;
}

export interface InterfaceFirewall {
  readonly protocol: "ĀML Interface Firewall";
  readonly version: "1.0";
  readonly profile: string;
  inspect(intent: AmlIntent, options?: InterfaceFirewallRunOptions): InterfaceInspection;
  enforce(intent: AmlIntent, options?: InterfaceFirewallRunOptions): InterfaceEnforcement;
}

export interface SemanticDiffNode {
  key: string;
  base_key: string;
  structural_path: string;
  type: string;
  name: string | null;
  identifier: string | null;
  properties: Record<string, unknown>;
  render_metadata: Record<string, unknown>;
  identity_ambiguous: boolean;
  identity_occurrence: number;
}

export interface SemanticDiffResult {
  protocol: "ĀML Semantic Diff";
  version: "1.0";
  meaning_equivalent: boolean;
  left_meaning_fingerprint: string;
  right_meaning_fingerprint: string;
  fingerprint_protocol: string;
  ambiguous_identity_keys: { key: string; count: number }[];
  identity_ambiguity_detected: boolean;
  summary: { added: number; removed: number; changed: number; unchanged: number };
  added: SemanticDiffNode[];
  removed: SemanticDiffNode[];
  changed: {
    key: string;
    identity_ambiguous: boolean;
    structural_changes: Record<string, { before: unknown; after: unknown }>;
    property_changes: Record<string, { before: unknown; after: unknown }>;
    meaning_changes: Record<string, { before: unknown; after: unknown }>;
  }[];
  unchanged: string[];
}

export interface AmlPolicyObject {
  id?: string;
  evaluate(element: Record<string, unknown>, execution?: {
    node?: unknown;
    metadata?: Record<string, unknown>;
    context?: AmlContext;
  }): { render_allowed: boolean; policy_id?: string; rationale?: unknown; [key: string]: unknown };
}

export type AmlPolicyFunction = AmlPolicyObject["evaluate"];

export type AmlPolicyTarget = string | AmlPolicyObject | {
  id?: string;
  description?: string;
  policies: string[];
};

export interface PolicyDiffResult {
  protocol: "ĀML Policy Diff";
  version: "1.0";
  context: AmlContext;
  left: { id: string; kind: "policy" | "profile" };
  right: { id: string; kind: "policy" | "profile" };
  ambiguous_identity_keys: { key: string; count: number }[];
  identity_ambiguity_detected: boolean;
  changed_decisions: number;
  changes: {
    key: string;
    identity_ambiguous: boolean;
    left: { render_allowed: boolean; policy_id: string; rationale: unknown } | null;
    right: { render_allowed: boolean; policy_id: string; rationale: unknown } | null;
  }[];
}

export interface PolicySimulationResult {
  protocol: "ĀML Counterfactual Policy Simulation";
  version: "1.0";
  policy_count: number;
  decision_nodes: number;
  context: AmlContext;
  runs: {
    policy: string;
    allowed: number;
    suppressed: number;
    decisions: RenderDecision[];
  }[];
}

export interface ViewMeaningReport {
  protocol: "ĀML View Meaning";
  version: "1.0";
  profile: string | null;
  summary: {
    total_nodes: number;
    allowed: number;
    suppressed: number;
    attention_consumed: number | null;
    attention_remaining: number | null;
    runtime_audit_verified: boolean;
  };
  nodes: {
    identifier: string | null;
    node_type: string | null;
    purpose: string | null;
    attention_cost: number | null;
    restoration_value: number | null;
    policy_id: string | null;
    render_allowed: boolean;
    rationale: unknown;
    fallback_triggered: boolean;
  }[];
  integrity: {
    receipt_sha256: string | null;
    audit_stream_sha256: string | null;
    attention_ledger_sha256: string | null;
    signed: boolean;
  };
}

export interface DeploymentOptions {
  profile?: string;
  mode?: AmlMode;
  failure_mode?: AmlFailureMode;
  context?: AmlContext;
  timestamp?: string;
  stream_id?: string;
  cache_key?: string;
  cache?: unknown;
}

export interface DeploymentResult {
  protocol: "ĀML Deployment Firewall Result";
  mode: AmlMode;
  failure_mode: AmlFailureMode;
  profile: string;
  aml_allowed: boolean | null;
  effective_allowed: boolean;
  would_suppress: boolean;
  evaluation_error: { name: string; message: string; code: string } | null;
  result: { allowed: boolean; receipt?: ExecutionReceipt; [key: string]: unknown } | null;
}

export interface DeploymentFirewall {
  readonly mode: AmlMode;
  readonly failure_mode: AmlFailureMode;
  readonly profile: string;
  evaluate(intent: AmlIntent, options?: DeploymentOptions): DeploymentResult;
  enforce(intent: AmlIntent, options?: DeploymentOptions): DeploymentResult;
  shadow(intent: AmlIntent, options?: DeploymentOptions): DeploymentResult;
  cache_stats(): unknown;
}

export interface AgentUiComponent {
  id?: string;
  identifier?: string;
  type?: string;
  props?: Record<string, unknown>;
  governance?: Record<string, unknown> & {
    purpose: string;
    attention_cost: number;
    restoration_value: number;
  };
  aml?: Record<string, unknown> & {
    purpose: string;
    attention_cost: number;
    restoration_value: number;
  };
  [key: string]: unknown;
}

export interface AgentUiEnvelope {
  protocol?: "aml-agent-ui-envelope/1";
  surface_id?: string;
  components: AgentUiComponent[];
}

export interface AgentUiOptions {
  profile?: string;
  mode?: AmlMode;
  failure_mode?: AmlFailureMode;
  context?: AmlContext;
  timestamp?: string;
}

export interface AgentUiDecision {
  id: string;
  component_type: string;
  aml_allowed: boolean | null;
  effective_allowed: boolean;
  would_suppress: boolean;
  evaluation_error: unknown;
  receipt_sha256: string | null;
  output_sha256: string | null;
}

export interface AgentUiGovernanceResult {
  protocol: "aml-agent-ui-governance-result/1";
  surface_id: string;
  mode: AmlMode;
  policy_profile: string;
  total: number;
  allowed: number;
  suppressed: number;
  errors: number;
  decisions: AgentUiDecision[];
  renderable_components: AgentUiComponent[];
  suppressed_components: AgentUiComponent[];
  streaming_result: unknown;
}

export interface GovernanceStreamOpen {
  protocol?: "aml-governance-stream-open/1";
  transmission?: string;
  profile?: string;
  mode?: AmlMode;
  failure_mode?: AmlFailureMode;
  context?: AmlContext;
  timestamp?: string;
  policy_authorization?: Record<string, unknown>;
}

export interface GovernanceStreamNode {
  protocol: "aml-governance-stream-node/1";
  node: AmlIntentNode;
  profile?: string;
  mode?: AmlMode;
  failure_mode?: AmlFailureMode;
  context?: AmlContext;
  timestamp?: string;
}

export interface GovernanceStreamPolicyUpdate {
  protocol: "aml-governance-stream-policy-update/1";
  profile?: string;
  mode?: AmlMode;
  failure_mode?: AmlFailureMode;
  context?: AmlContext;
  context_mode?: string;
  authorization?: unknown;
}

export interface GovernanceStreamFinalize {
  protocol: "aml-governance-stream-finalize/1";
}

export type GovernanceStreamMessage = GovernanceStreamNode | GovernanceStreamPolicyUpdate | GovernanceStreamFinalize;

export interface GovernanceStreamSession {
  readonly protocol: "aml-governance-stream-open/1";
  readonly transmission: string;
  readonly profile: string;
  readonly mode: AmlMode;
  readonly failure_mode: AmlFailureMode;
  readonly policy_epoch: number;
  readonly policy_sha256: string;
  readonly finalized: boolean;
  accept(message: GovernanceStreamMessage): { protocol: string; [key: string]: unknown };
  snapshot(): unknown;
}

export interface AmlHttpRequest {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  rawHeaders: string[];
}

export interface AmlHttpServer {
  listen(port: number, listener?: () => void): AmlHttpServer;
  listen(port: number, host: string, listener?: () => void): AmlHttpServer;
  close(listener?: (error?: Error) => void): AmlHttpServer;
  address(): string | { address: string; family: string; port: number } | null;
}

export type RequestAuthenticator =
  | { bearer_token: string }
  | ((request: AmlHttpRequest) => boolean | Promise<boolean>);

export interface LockedHttpPolicy {
  profile?: string;
  mode?: AmlMode;
  failure_mode?: AmlFailureMode;
  context?: AmlContext;
  resolve_context?: (request: AmlHttpRequest) => AmlContext | Promise<AmlContext>;
  max_batch_items?: number;
}

export interface AmlHttpServerOptions {
  default_profile?: string;
  allowed_origin?: string | null;
  max_body_bytes?: number;
  max_batch_items?: number;
  brand_trust_roots?: unknown;
  request_auth?: RequestAuthenticator;
  locked_policy?: LockedHttpPolicy;
}

export interface AgentUiGatewayOptions {
  default_profile?: string;
  default_mode?: AmlMode;
  default_failure_mode?: AmlFailureMode;
  max_body_bytes?: number;
  max_components?: number;
  request_auth?: RequestAuthenticator;
  locked_policy?: LockedHttpPolicy;
}

export interface GovernanceStreamGatewayOptions {
  max_line_bytes?: number;
  max_stream_bytes?: number;
  max_messages?: number;
  request_auth?: RequestAuthenticator;
  locked_policy?: LockedHttpPolicy;
}

export interface AmlDoctorCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface AmlDoctorReport {
  protocol: "aml-doctor-report/1";
  healthy: boolean;
  package?: string;
  version?: string;
  node?: string;
  platform?: string;
  architecture?: string;
  checks: AmlDoctorCheck[];
  claim_boundary?: string;
}

export function compileAML(inputPath: string, outputDir?: string, options?: CompileOptions): CompileFileResult;
export function compileSource(source: string, options?: CompileOptions): CompileResult;
export function generateAMLFromIntent(intent: AmlIntent): string;
export function executeAccountableIntent(intent: AmlIntent, options?: DeploymentOptions): ExecutionReceipt;
export function verifyExecutionReceipt(receipt: ExecutionReceipt): ReceiptVerification;
export function createDeploymentFirewall(options?: DeploymentOptions): DeploymentFirewall;
export function evaluateDeploymentIntent(intent: AmlIntent, options?: DeploymentOptions): DeploymentResult;
export function simulatePolicies(source: string, policies: (string | AmlPolicyObject | AmlPolicyFunction)[], options?: { timestamp?: string; context?: AmlContext }): PolicySimulationResult;
export function semanticDiff(beforeSource: string, afterSource: string, options?: CompileOptions): SemanticDiffResult;
export function policyDiff(source: string, left: AmlPolicyTarget, right: AmlPolicyTarget, options?: { timestamp?: string; context?: AmlContext }): PolicyDiffResult;
export function ethicalRenderGate(input: unknown, context?: AmlContext): unknown;
export function createInterfaceFirewall(options?: InterfaceFirewallOptions): InterfaceFirewall;
export function enforceInterfaceIntent(intent: AmlIntent, options?: InterfaceFirewallRunOptions): InterfaceEnforcement;
export function viewMeaning(receipt: ExecutionReceipt): ViewMeaningReport;
export function formatMeaningReport(report: ViewMeaningReport): string;
export function evaluateAgentUI(input: AgentUiEnvelope, options?: AgentUiOptions): AgentUiGovernanceResult;
export function createGovernanceStreamSession(open?: GovernanceStreamOpen): GovernanceStreamSession;
export function createGovernanceStreamTranscript(messages: unknown[], options?: Record<string, unknown>): unknown;
export function verifyGovernanceStreamTranscript(transcript: unknown, options?: Record<string, unknown>): unknown;
export function signGovernanceStreamTranscript(transcript: unknown, privateKey: string | Uint8Array, options?: Record<string, unknown>): unknown;
export function verifySignedGovernanceStreamTranscript(input: unknown, options?: Record<string, unknown>): unknown;
export function evaluateGovernanceWitnessQuorum(input: unknown, policy?: Record<string, unknown>): unknown;
export function localizeRuntimeDisagreement(left: unknown, right: unknown, options?: Record<string, unknown>): unknown;
export function createGovernanceDisclosure(input: unknown, options?: Record<string, unknown>): unknown;
export function verifyGovernanceDisclosure(input: unknown, options?: Record<string, unknown>): unknown;
export function createGovernancePolicyTransition(input: unknown, options?: Record<string, unknown>): unknown;
export function createAmlHttpServer(options?: AmlHttpServerOptions): AmlHttpServer;
export function createAgentUiGateway(options?: AgentUiGatewayOptions): AmlHttpServer;
export function createGovernanceStreamGateway(options?: GovernanceStreamGatewayOptions): AmlHttpServer;
export function runAmlDoctor(options?: Record<string, unknown>): AmlDoctorReport;

export const AML_AGENT_UI_ENVELOPE: "aml-agent-ui-envelope/1";
export const AML_AGENT_UI_RESULT: "aml-agent-ui-governance-result/1";
export const AML_GOVERNANCE_STREAM_OPEN: "aml-governance-stream-open/1";
export const AML_GOVERNANCE_STREAM_NODE: "aml-governance-stream-node/1";
export const AML_GOVERNANCE_STREAM_DECISION: "aml-governance-stream-decision/1";
export const AML_GOVERNANCE_STREAM_POLICY_UPDATE: "aml-governance-stream-policy-update/1";
export const AML_GOVERNANCE_STREAM_POLICY_APPLIED: "aml-governance-stream-policy-applied/1";
export const AML_GOVERNANCE_STREAM_FINALIZE: "aml-governance-stream-finalize/1";
export const AML_GOVERNANCE_STREAM_RESULT: "aml-governance-stream-result/1";
export const AML_GOVERNANCE_STREAM_ERROR: "aml-governance-stream-error/1";
export const AML_GOVERNANCE_TRANSCRIPT: string;
export const AML_SIGNED_GOVERNANCE_TRANSCRIPT: string;
export const AML_GOVERNANCE_WITNESS_QUORUM: string;
export const AML_RUNTIME_DISAGREEMENT_REPORT: string;
export const AML_GOVERNANCE_DISCLOSURE: string;
export const AML_GOVERNANCE_POLICY_TRANSITION: string;
