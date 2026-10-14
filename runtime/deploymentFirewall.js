// runtime/deploymentFirewall.js
// Production rollout wrapper for the core AML Interface Firewall.
// Supports enforce/shadow operation, explicit failure policy, and safe bounded caching.

import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createInterfaceFirewall } from "./interfaceFirewall.js";

const MODES = new Set(["enforce", "shadow"]);
const FAILURE_MODES = new Set(["closed", "open"]);

function sha256(value) {
  return crypto.createHash("sha256").update(canonicalJSONStringify(value)).digest("hex");
}

function normalizeMode(value, allowed, name) {
  if (!allowed.has(value)) {
    throw new Error(`${name} must be one of: ${[...allowed].join(", ")}.`);
  }
  return value;
}

function cacheInput(intent, profile, context, timestamp, streamId, mode, failureMode, manualKey) {
  // An explicit key is a namespace, never a substitute for the evaluated inputs.
  // A dynamic timestamp can affect policy and receipts even with a manual key.
  if (!timestamp) return null;
  // Use the same snapshot for evaluation and the key. Otherwise a getter or a
  // mutated custom profile can make the cached decision describe other inputs.
  const input = JSON.parse(canonicalJSONStringify({
    intent, profile, context, timestamp, stream_id: streamId || null
  }));
  const namespace = typeof manualKey === "string" && manualKey.length > 0 ? manualKey : null;
  return {
    input,
    key: `${namespace === null ? "auto" : "manual"}:${sha256({
      ...input, mode, failure_mode: failureMode, namespace
    })}`
  };
}

function sameProfile(left, right) {
  return canonicalJSONStringify(left) === canonicalJSONStringify(right);
}

function normalizeError(error) {
  return {
    name: error?.name || "Error",
    message: error?.message || String(error),
    code: error?.code || "AML_DEPLOYMENT_EVALUATION_FAILED"
  };
}

export function createDeploymentFirewall(options = {}) {
  const mode = normalizeMode(options.mode || "enforce", MODES, "mode");
  const failureMode = normalizeMode(options.failure_mode || "closed", FAILURE_MODES, "failure_mode");
  const profile = options.profile || "human_first";
  const defaultContext = structuredClone(options.context || {});
  const cache = options.cache || null;
  const core = createInterfaceFirewall({ profile, context: defaultContext });

  function evaluate(intent, runOptions = {}) {
    const selectedMode = normalizeMode(runOptions.mode || mode, MODES, "mode");
    const selectedFailureMode = normalizeMode(
      runOptions.failure_mode || failureMode,
      FAILURE_MODES,
      "failure_mode"
    );
    const selectedProfile = runOptions.profile || profile;
    const context = { ...defaultContext, ...(runOptions.context || {}) };
    const timestamp = runOptions.timestamp;
    const streamId = runOptions.stream_id;
    let snapshot = null;
    try {
      if (cache) snapshot = cacheInput(intent, selectedProfile, context, timestamp, streamId,
        selectedMode, selectedFailureMode, runOptions.cache_key);
    } catch {
      // Unsupported/cyclic inputs cannot be safely cached. Let the evaluator
      // determine their ordinary success or failure under the selected mode.
    }
    const cacheKey = snapshot?.key ?? null;

    if (cache && cacheKey) {
      try {
        const cached = cache.get(cacheKey);
        if (cached && cached.mode === selectedMode && cached.failure_mode === selectedFailureMode &&
            sameProfile(cached.profile, snapshot.input.profile)) {
          return { ...cached, cache: { enabled: true, hit: true, key: cacheKey } };
        }
      } catch { /* An optional cache failure must not replace the live decision. */ }
    }

    try {
      const result = core.enforce(snapshot?.input.intent ?? intent, {
        profile: snapshot?.input.profile ?? selectedProfile,
        context: snapshot?.input.context ?? context,
        timestamp: snapshot?.input.timestamp ?? timestamp,
        stream_id: snapshot?.input.stream_id ?? streamId
      });
      const amlAllowed = result.allowed;
      const effectiveAllowed = selectedMode === "shadow" ? true : amlAllowed;
      const deployment = {
        protocol: "ĀML Deployment Firewall Result",
        version: "1.0",
        mode: selectedMode,
        failure_mode: selectedFailureMode,
        profile: snapshot?.input.profile ?? selectedProfile,
        aml_allowed: amlAllowed,
        effective_allowed: effectiveAllowed,
        would_suppress: !amlAllowed,
        evaluation_error: null,
        cache: { enabled: Boolean(cache), hit: false, key: cacheKey },
        result
      };
      if (cache && cacheKey) {
        try { cache.set(cacheKey, deployment); }
        catch { /* The computed decision still stands when caching fails. */ }
      }
      return deployment;
    } catch (error) {
      const effectiveAllowed = selectedFailureMode === "open";
      return {
        protocol: "ĀML Deployment Firewall Result",
        version: "1.0",
        mode: selectedMode,
        failure_mode: selectedFailureMode,
        profile: selectedProfile,
        aml_allowed: null,
        effective_allowed: effectiveAllowed,
        would_suppress: selectedFailureMode === "closed",
        evaluation_error: normalizeError(error),
        cache: { enabled: Boolean(cache), hit: false, key: cacheKey },
        result: null
      };
    }
  }

  return {
    protocol: "ĀML Deployment Firewall",
    version: "1.0",
    mode,
    failure_mode: failureMode,
    profile,
    evaluate,
    enforce(intent, runOptions = {}) {
      return evaluate(intent, { ...runOptions, mode: "enforce" });
    },
    shadow(intent, runOptions = {}) {
      return evaluate(intent, { ...runOptions, mode: "shadow" });
    },
    cache_stats() {
      return cache?.stats ? cache.stats() : null;
    }
  };
}

export function evaluateDeploymentIntent(intent, options = {}) {
  return createDeploymentFirewall(options).evaluate(intent, options);
}
