import crypto from "node:crypto";
import { createStreamingInterfaceFirewall } from "../runtime/streamingInterfaceFirewall.js";
import { canonicalJSONStringify } from "./canonicalJson.js";

export const AML_GOVERNANCE_STREAM_OPEN = "aml-governance-stream-open/1";
export const AML_GOVERNANCE_STREAM_NODE = "aml-governance-stream-node/1";
export const AML_GOVERNANCE_STREAM_DECISION = "aml-governance-stream-decision/1";
export const AML_GOVERNANCE_STREAM_POLICY_UPDATE = "aml-governance-stream-policy-update/1";
export const AML_GOVERNANCE_STREAM_POLICY_APPLIED = "aml-governance-stream-policy-applied/1";
export const AML_GOVERNANCE_STREAM_FINALIZE = "aml-governance-stream-finalize/1";
export const AML_GOVERNANCE_STREAM_RESULT = "aml-governance-stream-result/1";
export const AML_GOVERNANCE_STREAM_ERROR = "aml-governance-stream-error/1";

const MODES = new Set(["enforce", "shadow"]);
const FAILURE_MODES = new Set(["closed", "open"]);

function assertObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(canonicalJSONStringify(value)).digest("hex");
}

function validatePolicyState(state) {
  if (typeof state.profile !== "string" || state.profile.length === 0) throw new Error("profile must be a non-empty string");
  if (!MODES.has(state.mode)) throw new Error("mode must be enforce or shadow");
  if (!FAILURE_MODES.has(state.failure_mode)) throw new Error("failure_mode must be closed or open");
  assertObject(state.context, "policy context");
}

export function createGovernanceStreamSession(open = {}) {
  assertObject(open, "open");
  if (open.protocol && open.protocol !== AML_GOVERNANCE_STREAM_OPEN) {
    throw new Error(`Unsupported governance stream protocol: ${open.protocol}`);
  }

  const transmission = open.transmission || "governance_stream";
  let profile = open.profile || "calm_default";
  let mode = open.mode || "enforce";
  let failureMode = open.failure_mode || "closed";
  let context = structuredClone(open.context || {});
  const timestamp = open.timestamp;
  let policyEpoch = 0;
  validatePolicyState({ profile, mode, failure_mode: failureMode, context });

  const firewall = createStreamingInterfaceFirewall({
    transmission,
    profile,
    mode,
    failure_mode: failureMode,
    context
  });

  let finalized = false;

  function policyState() {
    return { profile, mode, failure_mode: failureMode, context: structuredClone(context) };
  }

  function accept(message) {
    assertObject(message, "message");
    if (finalized) throw new Error("AML_GOVERNANCE_STREAM_ALREADY_FINALIZED");

    if (message.protocol === AML_GOVERNANCE_STREAM_POLICY_UPDATE) {
      const previous = policyState();
      const next = {
        profile: message.profile ?? profile,
        mode: message.mode ?? mode,
        failure_mode: message.failure_mode ?? failureMode,
        context: message.context_mode === "replace"
          ? structuredClone(message.context || {})
          : { ...context, ...(message.context || {}) }
      };
      validatePolicyState(next);
      profile = next.profile;
      mode = next.mode;
      failureMode = next.failure_mode;
      context = next.context;
      policyEpoch += 1;
      return {
        protocol: AML_GOVERNANCE_STREAM_POLICY_APPLIED,
        transmission,
        policy_epoch: policyEpoch,
        previous_policy_sha256: sha256(previous),
        policy_sha256: sha256(policyState()),
        profile,
        mode,
        failure_mode: failureMode,
        context_sha256: sha256(context)
      };
    }

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
        entries: result.entries,
        policy_epochs: policyEpoch
      };
    }

    throw new Error(`Unsupported governance stream message protocol: ${message.protocol || "missing"}`);
  }

  return {
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    transmission,
    get profile() { return profile; },
    get mode() { return mode; },
    get failure_mode() { return failureMode; },
    get policy_epoch() { return policyEpoch; },
    accept,
    snapshot() {
      return firewall.snapshot();
    },
    get finalized() {
      return finalized;
    }
  };
}
