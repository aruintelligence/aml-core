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

function makeCacheKey(intent, profile, context, runOptions) {
  if (typeof runOptions.cache_key === "string" && runOptions.cache_key.length > 0) {
    return `manual:${runOptions.cache_key}`;
  }
  // Time can affect policy semantics. Refuse implicit caching without a fixed timestamp.
  if (!runOptions.timestamp) return null;
  return `auto:${sha256({ intent, profile, context, timestamp: runOptions.timestamp })}`;
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
    const cacheKey = cache ? makeCacheKey(intent, selectedProfile, context, runOptions) : null;

    if (cache && cacheKey) {
      const cached = cache.get(cacheKey);
      if (cached) {
        return {
          ...cached,
          cache: { enabled: true, hit: true, key: cacheKey }
        };
      }
    }

    try {
      const result = core.enforce(intent, {
        ...runOptions,
        profile: selectedProfile,
        context
      });
      const amlAllowed = result.allowed;
      const effectiveAllowed = selectedMode === "shadow" ? true : amlAllowed;
      const deployment = {
        protocol: "ĀML Deployment Firewall Result",
        version: "1.0",
        mode: selectedMode,
        failure_mode: selectedFailureMode,
        profile: selectedProfile,
        aml_allowed: amlAllowed,
        effective_allowed: effectiveAllowed,
        would_suppress: !amlAllowed,
        evaluation_error: null,
        cache: { enabled: Boolean(cache), hit: false, key: cacheKey },
        result
      };
      if (cache && cacheKey) cache.set(cacheKey, deployment);
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
