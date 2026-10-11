// Process-local illustration of a host-owned approval store. A production host
// needs a durable atomic claim shared by all workers and its own identity checks.
import { randomUUID } from "node:crypto";

const DIGEST = /^[a-f0-9]{64}$/;

export function createLocalOneShotGrants({ now = () => Date.now() } = {}) {
  if (typeof now !== "function") throw new TypeError("Invalid host clock");
  const grants = new Map();

  function issue(proposal_sha256, { ttlMs = 60_000 } = {}) {
    if (typeof proposal_sha256 !== "string" || !DIGEST.test(proposal_sha256) ||
        !Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > 300_000) {
      throw new TypeError("A valid digest and a positive TTL of at most five minutes are required");
    }
    const issuedAt = now();
    const approval_id = randomUUID();
    if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(issuedAt + ttlMs) ||
        grants.has(approval_id)) throw new Error("Invalid host clock or duplicate grant ID");
    grants.set(approval_id, { proposal_sha256, expiresAt: issuedAt + ttlMs });
    return { approved: true, proposal_sha256, approval_id };
  }

  function consume({ approval, proposal_sha256 } = {}) {
    if (!approval || typeof approval.approval_id !== "string") return false;
    const grant = grants.get(approval.approval_id);
    if (!grant) return false;
    if (now() >= grant.expiresAt) { grants.delete(approval.approval_id); return false; }
    if (grant.proposal_sha256 !== proposal_sha256 || approval.proposal_sha256 !== proposal_sha256) return false;
    // This is a synchronous claim in one Node process. No await occurs between
    // checking the grant and removing it, so concurrent calls cannot both pass.
    grants.delete(approval.approval_id);
    return true;
  }

  return { issue, consume };
}
