// Process-local reference for a host-owned approval-to-callback boundary.
// The host must authenticate approval and own all inputs and the callback.
// No await occurs between the final epoch check, the one-use claim, and
// invoking the callback. This is not a cross-process or provider-side lock.
import { randomUUID } from "node:crypto";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { hashHandoffBytes as digest, validHandoffIdentity as identity,
  snapshotHandoffBinding as binding } from "./handoff-binding.mjs";

const issuerKey = (tenant, issuer) => JSON.stringify([tenant, issuer]);

export function createLocalRevocationHandoff({ now = () => Date.now() } = {}) {
  if (typeof now !== "function") throw new TypeError("A host clock is required");
  const epochs = new Map();
  const grants = new Map();
  let lastTime = -Infinity;

  function hostTime() {
    const time = now();
    if (!Number.isSafeInteger(time) || time < lastTime) throw new Error("host_clock_unavailable");
    lastTime = time;
    return time;
  }

  function revokeIssuer({ tenant, issuer } = {}) {
    if (!identity(tenant) || !identity(issuer)) throw new TypeError("Invalid tenant or issuer");
    const key = issuerKey(tenant, issuer);
    const next = (epochs.get(key) ?? 0) + 1;
    if (!Number.isSafeInteger(next)) throw new Error("revocation_epoch_exhausted");
    epochs.set(key, next); // Same synchronous authority boundary as dispatch admission.
    return { tenant, issuer, epoch: next };
  }

  function issue(input, { ttlMs = 60_000 } = {}) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > 300_000) {
      throw new TypeError("TTL must be between 1 ms and five minutes");
    }
    const bound = binding(input);
    const issuedAt = hostTime();
    if (!Number.isSafeInteger(issuedAt + ttlMs)) throw new Error("host_clock_unavailable");
    const grantId = randomUUID();
    if (grants.has(grantId)) throw new Error("duplicate_grant_id");
    grants.set(grantId, { bound, issuedAt, expiresAt: issuedAt + ttlMs,
      epoch: epochs.get(issuerKey(bound.context.tenant, bound.context.issuer)) ?? 0,
      state: "issued" });
    return { grant_id: grantId, binding_sha256: bound.sha256,
      prepared_request_sha256: bound.request.sha256, policy_sha256: bound.policy.sha256 };
  }

  async function dispatch({ grant_id, execute, ...input } = {}) {
    const blocked = reason => ({ status: "blocked", reason, dispatch_count: 0 });
    if (typeof execute !== "function") return blocked("missing_host_dispatch");
    const grant = grants.get(grant_id);
    if (!grant || grant.state !== "issued") return blocked("grant_missing_or_spent");
    let bound, time;
    try {
      bound = binding(input);
      time = hostTime();
    } catch {
      return blocked("authority_input_or_clock_invalid");
    }
    if (bound.sha256 !== grant.bound.sha256) return blocked("binding_mismatch");
    if (time < grant.issuedAt || time >= grant.expiresAt) {
      grant.state = "expired";
      return blocked("grant_expired");
    }
    const currentEpoch = epochs.get(issuerKey(bound.context.tenant, bound.context.issuer));
    if (!Number.isSafeInteger(currentEpoch ?? 0) || (currentEpoch ?? 0) !== grant.epoch) {
      grant.state = "revoked";
      return blocked("issuer_revoked");
    }
    // The local linearization point. No user callback or await can interleave
    // between the epoch read, spending the grant, and invoking execute.
    grant.state = "handoff_started";
    const idempotencyKey = digest(canonicalJSONStringify([bound.context.tenant, grant_id]));
    let response;
    try {
      response = execute(JSON.parse(bound.request.bytes), { idempotencyKey });
    } catch {
      grant.state = "outcome_unknown";
      return { status: "outcome_unknown", reason: "callback_threw", dispatch_count: 1 };
    }
    try {
      const result = await response;
      grant.state = "returned";
      return { status: "returned", reason: "callback_returned", dispatch_count: 1, result };
    } catch {
      grant.state = "outcome_unknown";
      return { status: "outcome_unknown", reason: "callback_rejected", dispatch_count: 1 };
    }
  }

  return { issue, revokeIssuer, dispatch };
}
