import { createStreamingInterfaceFirewall } from "../runtime/streamingInterfaceFirewall.js";

export const AML_GOVERNANCE_STREAM_OPEN = "aml-governance-stream-open/1";
export const AML_GOVERNANCE_STREAM_NODE = "aml-governance-stream-node/1";
export const AML_GOVERNANCE_STREAM_DECISION = "aml-governance-stream-decision/1";
export const AML_GOVERNANCE_STREAM_FINALIZE = "aml-governance-stream-finalize/1";
export const AML_GOVERNANCE_STREAM_RESULT = "aml-governance-stream-result/1";
export const AML_GOVERNANCE_STREAM_ERROR = "aml-governance-stream-error/1";

function assertObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
}

export function createGovernanceStreamSession(open = {}) {
  assertObject(open, "open");
  if (open.protocol && open.protocol !== AML_GOVERNANCE_STREAM_OPEN) {
    throw new Error(`Unsupported governance stream protocol: ${open.protocol}`);
  }

  const transmission = open.transmission || "governance_stream";
  const profile = open.profile || "calm_default";
  const mode = open.mode || "enforce";
  const failureMode = open.failure_mode || "closed";
  const context = open.context || {};
  const timestamp = open.timestamp;

  const firewall = createStreamingInterfaceFirewall({
    transmission,
    profile,
    mode,
    failure_mode: failureMode,
    context
  });

  let finalized = false;

  function accept(message) {
    assertObject(message, "message");
    if (finalized) throw new Error("AML_GOVERNANCE_STREAM_ALREADY_FINALIZED");

    if (message.protocol === AML_GOVERNANCE_STREAM_NODE) {
      assertObject(message.node, "message.node");
      const evaluated = firewall.push(message.node, {
        timestamp: message.timestamp || timestamp,
        context: { ...context, ...(message.context || {}) },
        mode: message.mode || mode,
        failure_mode: message.failure_mode || failureMode,
        profile: message.profile || profile
      });
      return {
        protocol: AML_GOVERNANCE_STREAM_DECISION,
        transmission,
        sequence: evaluated.sequence,
        identifier: evaluated.identifier,
        aml_allowed: evaluated.aml_allowed,
        effective_allowed: evaluated.effective_allowed,
        would_suppress: evaluated.would_suppress,
        evaluation_error: evaluated.evaluation_error,
        receipt_sha256: evaluated.receipt_sha256,
        output_sha256: evaluated.output_sha256
      };
    }

    if (message.protocol === AML_GOVERNANCE_STREAM_FINALIZE) {
      finalized = true;
      const result = firewall.finalize();
      return {
        protocol: AML_GOVERNANCE_STREAM_RESULT,
        transmission,
        finalized: true,
        total: result.total,
        allowed: result.allowed,
        suppressed: result.suppressed,
        errors: result.errors,
        effective_allowed: result.effective_allowed,
        entries: result.entries
      };
    }

    throw new Error(`Unsupported governance stream message protocol: ${message.protocol || "missing"}`);
  }

  return {
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission,
    profile,
    mode,
    failure_mode: failureMode,
    accept,
    snapshot() {
      return firewall.snapshot();
    },
    get finalized() {
      return finalized;
    }
  };
}
