export interface AmlDoctorCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface AmlDoctorReport {
  protocol: 'aml-doctor-report/1';
  healthy: boolean;
  package?: string;
  version?: string;
  node?: string;
  platform?: string;
  architecture?: string;
  checks: AmlDoctorCheck[];
  claim_boundary?: string;
}

export interface CompileResult {
  source?: string;
  ast?: unknown;
  amt?: unknown;
  [key: string]: unknown;
}

export interface InterfaceGovernanceDecision {
  id?: string;
  render?: boolean;
  decision?: 'ALLOW' | 'SUPPRESS' | string;
  [key: string]: unknown;
}

export interface AgentUiGovernanceResult {
  protocol?: string;
  renderable?: unknown[];
  suppressed?: unknown[];
  decisions?: InterfaceGovernanceDecision[];
  [key: string]: unknown;
}

export interface GovernanceStreamSession {
  handle(message: unknown): unknown;
  finalize?(): unknown;
  [key: string]: unknown;
}

export function compileAML(source: string, options?: Record<string, unknown>): CompileResult;
export function compileSource(source: string, options?: Record<string, unknown>): CompileResult;
export function generateAMLFromIntent(intent: unknown, options?: Record<string, unknown>): unknown;
export function simulatePolicies(input: unknown, policies?: unknown): unknown;
export function semanticDiff(before: unknown, after: unknown, options?: Record<string, unknown>): unknown;
export function policyDiff(before: unknown, after: unknown, options?: Record<string, unknown>): unknown;
export function ethicalRenderGate(input: unknown, context?: Record<string, unknown>): unknown;
export function createInterfaceFirewall(options?: Record<string, unknown>): unknown;
export function enforceInterfaceIntent(input: unknown, options?: Record<string, unknown>): unknown;
export function evaluateAgentUI(input: unknown, options?: Record<string, unknown>): AgentUiGovernanceResult;
export function createGovernanceStreamSession(options?: Record<string, unknown>): GovernanceStreamSession;
export function createGovernanceStreamTranscript(messages: unknown[], options?: Record<string, unknown>): unknown;
export function verifyGovernanceStreamTranscript(transcript: unknown, options?: Record<string, unknown>): unknown;
export function signGovernanceStreamTranscript(transcript: unknown, privateKey: string | Uint8Array, options?: Record<string, unknown>): unknown;
export function verifySignedGovernanceStreamTranscript(input: unknown, options?: Record<string, unknown>): unknown;
export function evaluateGovernanceWitnessQuorum(input: unknown, policy?: Record<string, unknown>): unknown;
export function localizeRuntimeDisagreement(left: unknown, right: unknown, options?: Record<string, unknown>): unknown;
export function createGovernanceDisclosure(input: unknown, options?: Record<string, unknown>): unknown;
export function verifyGovernanceDisclosure(input: unknown, options?: Record<string, unknown>): unknown;
export function createGovernancePolicyTransition(input: unknown, options?: Record<string, unknown>): unknown;
export function createAmlHttpServer(options?: Record<string, unknown>): unknown;
export function createAgentUiGateway(options?: Record<string, unknown>): unknown;
export function createGovernanceStreamGateway(options?: Record<string, unknown>): unknown;
export function runAmlDoctor(options?: Record<string, unknown>): AmlDoctorReport;

export const AML_AGENT_UI_ENVELOPE: string;
export const AML_AGENT_UI_RESULT: string;
export const AML_GOVERNANCE_TRANSCRIPT: string;
export const AML_SIGNED_GOVERNANCE_TRANSCRIPT: string;
export const AML_GOVERNANCE_WITNESS_QUORUM: string;
export const AML_RUNTIME_DISAGREEMENT_REPORT: string;
export const AML_GOVERNANCE_DISCLOSURE: string;
export const AML_GOVERNANCE_POLICY_TRANSITION: string;
