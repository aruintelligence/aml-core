// A process-local illustration of an atomic, host-owned A2UI invocation ID
// claim. The host supplies the session identity; the agent never does.
// A production renderer needs a durable claim shared by every worker.
const text = value => typeof value === "string" && value.trim().length > 0 &&
  value.length <= 256;

export function createLocalA2UIInvocationClaims({ sessionFor, maxEntries = 10_000 } = {}) {
  if (typeof sessionFor !== "function" || !Number.isSafeInteger(maxEntries) ||
      maxEntries < 1) throw new TypeError("A host session resolver and positive capacity are required");
  const claimed = new Set();

  function claim({ functionCallId } = {}, context) {
    const sessionId = sessionFor(context);
    if (!text(sessionId) || !text(functionCallId)) {
      throw new TypeError("A trusted host session and A2UI functionCallId are required");
    }
    // A JSON tuple avoids ambiguous concatenation. The synchronous has/add
    // sequence has no await point within this one Node process.
    const key = JSON.stringify([sessionId, functionCallId]);
    if (claimed.has(key)) return false;
    if (claimed.size >= maxEntries) throw new Error("invocation_claim_capacity_exceeded");
    claimed.add(key);
    return true;
  }

  return { claim };
}
