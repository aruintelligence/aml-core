// A host-owned, local-filesystem one-use grant prototype. Workers sharing this
// directory race on exclusive creation of one claim marker. The directory must
// be private to the host; this is not a network-store or multi-machine protocol.
import { randomUUID } from "node:crypto";
import { mkdir, open, readFile } from "node:fs/promises";
import path from "node:path";

const DIGEST = /^[a-f0-9]{64}$/;
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function createFileOneShotGrants({ directory, now = () => Date.now() } = {}) {
  if (typeof directory !== "string" || !path.isAbsolute(directory) ||
      typeof now !== "function") {
    throw new TypeError("A trusted absolute directory and host clock are required");
  }
  const issued = path.join(directory, "issued");
  const claimed = path.join(directory, "claimed");

  async function prepare() {
    await mkdir(issued, { recursive: true, mode: 0o700 });
    await mkdir(claimed, { recursive: true, mode: 0o700 });
  }

  async function issue(proposal_sha256, { ttlMs = 60_000 } = {}) {
    if (typeof proposal_sha256 !== "string" || !DIGEST.test(proposal_sha256) ||
        !Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > 300_000) {
      throw new TypeError("A valid digest and a positive TTL of at most five minutes are required");
    }
    const issuedAt = now();
    if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(issuedAt + ttlMs)) {
      throw new Error("Invalid host clock");
    }
    await prepare();
    const approval_id = randomUUID();
    const file = path.join(issued, `${approval_id}.json`);
    const handle = await open(file, "wx", 0o600);
    try {
      await handle.writeFile(JSON.stringify({ approval_id, proposal_sha256,
        expires_at_ms: issuedAt + ttlMs }));
      await handle.sync();
    } finally {
      await handle.close();
    }
    return { approved: true, proposal_sha256, approval_id };
  }

  async function consume({ approval, proposal_sha256 } = {}) {
    const id = approval?.approval_id;
    if (typeof id !== "string" || !ID.test(id) || !DIGEST.test(proposal_sha256) ||
        approval.proposal_sha256 !== proposal_sha256) return false;
    let record;
    try {
      record = JSON.parse(await readFile(path.join(issued, `${id}.json`), "utf8"));
    } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error; // A storage or integrity error must fail closed at the boundary.
    }
    if (record.approval_id !== id || record.proposal_sha256 !== proposal_sha256 ||
        !Number.isSafeInteger(record.expires_at_ms)) return false;
    if (now() >= record.expires_at_ms) return false;

    // Exclusive creation is the linearization point on a local filesystem.
    // A crash after this succeeds leaves the grant spent before any callback.
    let marker;
    try {
      marker = await open(path.join(claimed, `${id}.claim`), "wx", 0o600);
    } catch (error) {
      if (error.code === "EEXIST") return false;
      throw error;
    }
    try {
      await marker.writeFile(JSON.stringify({ approval_id: id, proposal_sha256 }));
      await marker.sync();
    } finally {
      await marker.close();
    }
    // If time advanced during the claim, it remains spent and cannot dispatch.
    return now() < record.expires_at_ms;
  }

  return { issue, consume };
}
