function parseTimestamp(value) {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

export function createReplayGuard() {
  return { type: "aml-replay-guard/1", seen: {} };
}

export function acceptWireEnvelope(guard, envelope, { now = null } = {}) {
  if (!guard || guard.type !== "aml-replay-guard/1") throw new Error("Invalid replay guard");
  if (!envelope?.nonce) return { accepted: false, reason: "missing_nonce", guard };
  if (!envelope?.session_id) return { accepted: false, reason: "missing_session_id", guard };

  const nowTimestamp = now === null || now === undefined ? null : parseTimestamp(now);
  if (now !== null && now !== undefined && nowTimestamp === null) {
    return { accepted: false, reason: "invalid_now", guard };
  }

  const expiresAt = envelope.expires_at === null || envelope.expires_at === undefined
    ? null
    : parseTimestamp(envelope.expires_at);
  if (envelope.expires_at !== null && envelope.expires_at !== undefined && expiresAt === null) {
    return { accepted: false, reason: "invalid_expires_at", guard };
  }
  if (nowTimestamp !== null && expiresAt !== null && nowTimestamp >= expiresAt) {
    return { accepted: false, reason: "expired", guard };
  }

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
