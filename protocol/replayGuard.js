import { validateWireEnvelope } from "./wireProtocol.js";

export function createReplayGuard() {
  return { type: "aml-replay-guard/1", seen: {} };
}

export function acceptWireEnvelope(guard, envelope, { now = null, allowedKinds = [] } = {}) {
  if (!guard || guard.type !== "aml-replay-guard/1") throw new Error("Invalid replay guard");

  const validation = validateWireEnvelope(envelope, { allowedKinds, now });
  if (!validation.valid) return { accepted: false, reason: validation.reason, guard };
  if (!envelope?.nonce) return { accepted: false, reason: "missing_nonce", guard };
  if (!envelope?.session_id) return { accepted: false, reason: "missing_session_id", guard };

  const key = `${envelope.session_id}:${envelope.nonce}`;
  if (guard.seen[key]) return { accepted: false, reason: "replay", guard };

  return {
    accepted: true,
    reason: null,
    guard: {
      type: guard.type,
      seen: { ...guard.seen, [key]: envelope.issued_at ?? now ?? true }
    }
  };
}
