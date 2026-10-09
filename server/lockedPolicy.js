import { resolvePolicyProfile } from "../runtime/policyProfiles.js";
import { DEFAULT_TRUSTED_CALLBACK_TIMEOUT_MS, runTrustedCallback, validateTrustedCallbackTimeout } from "./trustedCallback.js";

const CONFIG_KEYS = new Set(["profile", "mode", "failure_mode", "context", "resolve_context", "resolve_context_timeout_ms", "max_batch_items"]);
const CLIENT_CONTROLS = ["profile", "mode", "failure_mode", "context", "timestamp", "max_items"];
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const plainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

function httpError(message, statusCode) {
  return Object.assign(new Error(message), { statusCode });
}

// Opt-in, server-owned deployment controls. Authentication and the provenance
// of a resolver's context remain responsibilities of the embedding service.
export function createLockedHttpPolicy(config, defaultProfile = "human_first") {
  if (config == null) return null;
  if (!plainObject(config)) throw new TypeError("locked_policy must be an object");
  for (const key of Object.keys(config)) {
    if (!CONFIG_KEYS.has(key)) throw new TypeError(`unknown locked_policy option: ${key}`);
  }

  const profile = config.profile ?? defaultProfile;
  if (typeof profile !== "string") throw new TypeError("locked_policy.profile must name a built-in profile");
  resolvePolicyProfile(profile);
  const mode = config.mode ?? "enforce";
  const failure_mode = config.failure_mode ?? "closed";
  if (mode !== "enforce" && mode !== "shadow") throw new TypeError("locked_policy.mode must be enforce or shadow");
  if (failure_mode !== "closed" && failure_mode !== "open") throw new TypeError("locked_policy.failure_mode must be closed or open");
  if (config.resolve_context != null && typeof config.resolve_context !== "function") {
    throw new TypeError("locked_policy.resolve_context must be a function");
  }
  if (config.resolve_context != null && own(config, "context")) {
    throw new TypeError("locked_policy.context and resolve_context are mutually exclusive");
  }
  const resolver = config.resolve_context ?? null;
  const resolverTimeout = validateTrustedCallbackTimeout(
    config.resolve_context_timeout_ms ?? DEFAULT_TRUSTED_CALLBACK_TIMEOUT_MS,
    "locked_policy.resolve_context_timeout_ms"
  );
  const context = config.context ?? {};
  if (!plainObject(context)) throw new TypeError("locked_policy.context must be an object");
  const staticContext = structuredClone(context);
  const max_batch_items = config.max_batch_items ?? 100;
  if (!Number.isSafeInteger(max_batch_items) || max_batch_items < 1) {
    throw new TypeError("locked_policy.max_batch_items must be a positive safe integer");
  }

  return Object.freeze({
    profile,
    mode,
    failure_mode,
    max_batch_items,
    async select(body, req) {
      if (!plainObject(body)) throw httpError("invalid_request_body", 400);
      if (CLIENT_CONTROLS.some((key) => own(body, key))) {
        throw httpError("policy_override_forbidden", 403);
      }

      let resolved;
      try {
        resolved = resolver ? await runTrustedCallback(resolver, req, resolverTimeout) : staticContext;
        if (!plainObject(resolved)) throw new TypeError("invalid trusted context");
        resolved = structuredClone(resolved);
      } catch {
        throw httpError("trusted_context_unavailable", 503);
      }

      return {
        profile,
        mode,
        failure_mode,
        context: resolved,
        timestamp: new Date().toISOString(),
        max_items: max_batch_items
      };
    }
  });
}
