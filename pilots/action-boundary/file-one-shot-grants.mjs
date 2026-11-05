// A host-owned, local-filesystem one-use grant prototype. Workers sharing this
// directory race on exclusive creation of one claim marker. The directory must
// be private to the host; this is not a network-store or multi-machine protocol.
import { randomUUID } from "node:crypto";
import { lstat, mkdir, open, readFile, readdir } from "node:fs/promises";
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
  const state = path.join(directory, "store-state.json");
  let prepared = false;

  async function syncDirectory(target) {
    const handle = await open(target, "r");
    try { await handle.sync(); } finally { await handle.close(); }
  }

  async function requirePrivateDirectory(target) {
    // mkdir's mode only applies to newly created directories. An existing
    // directory may be writable by someone who can replace a claim marker.
    const info = await lstat(target); // Do not follow a directory symlink.
    if (!info.isDirectory() || (info.mode & 0o077) !== 0 ||
        typeof process.getuid !== "function" || info.uid !== process.getuid()) {
      throw new Error("private_grant_directory_required");
    }
  }

  async function prepare() {
    // An instance that has used a store must not silently recreate a removed
    // root. A new instance also requires the state marker below.
    if (!prepared) await mkdir(directory, { recursive: true, mode: 0o700 });
    await requirePrivateDirectory(directory);
    let exists = true;
    try { await lstat(state); }
    catch (error) {
      if (error.code !== "ENOENT") throw error;
      exists = false;
    }
    if (!exists) {
      // Only an empty directory is a fresh store. In particular, a missing
      // marker next to old issued grants cannot be treated as initialization.
      if (prepared || (await readdir(directory)).length !== 0) {
        throw new Error("grant_store_incomplete");
      }
      let handle;
      try { handle = await open(state, "wx", 0o600); }
      catch (error) {
        if (error.code !== "EEXIST") throw error;
      }
      if (handle) {
        try {
          await handle.writeFile('{"protocol":"aml-file-one-shot-store/2"}\n');
          await handle.sync();
        } finally { await handle.close(); }
        await syncDirectory(directory);
        await mkdir(issued, { mode: 0o700 });
        await mkdir(claimed, { mode: 0o700 });
        await syncDirectory(directory);
      }
    }
    await verify();
    prepared = true;
  }

  async function verify() {
    // Consume must not silently recreate a lost claim directory: doing so
    // would forget spent grants. Recheck modes before accessing records.
    await requirePrivateDirectory(directory);
    await requirePrivateDirectory(issued);
    await requirePrivateDirectory(claimed);
    const info = await lstat(state);
    if (!info.isFile() || (info.mode & 0o077) !== 0 ||
        info.uid !== process.getuid() || info.size > 128 ||
        (await readFile(state, "utf8")) !== '{"protocol":"aml-file-one-shot-store/2"}\n') {
      throw new Error("grant_store_incomplete");
    }
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
    await syncDirectory(issued);
    return { approved: true, proposal_sha256, approval_id };
  }

  async function consume({ approval, proposal_sha256 } = {}) {
    const id = approval?.approval_id;
    if (typeof id !== "string" || !ID.test(id) || !DIGEST.test(proposal_sha256) ||
        approval.proposal_sha256 !== proposal_sha256) return false;
    await verify();
    let record;
    try {
      record = JSON.parse(await readFile(path.join(issued, `${id}.json`), "utf8"));
    } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error; // A storage or integrity error must fail closed at the boundary.
    }
    if (record.approval_id !== id || record.proposal_sha256 !== proposal_sha256 ||
        !Number.isSafeInteger(record.expires_at_ms)) return false;
    await verify();

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
    // fsync of the file alone does not guarantee that its directory entry
    // survives a power loss. Do not report a spent grant before syncing it.
    await syncDirectory(claimed);
    // Even an expired grant is spent when first observed. A later host-clock
    // rollback cannot revive that observed grant after a process restart.
    // An unobserved expiry still requires a trustworthy clock/anchor.
    return now() < record.expires_at_ms;
  }

  // Call once before starting concurrent issuers. The same validation is
  // applied by issue(), so this does not relax integrity checks or migrate
  // an incomplete store.
  return { initialize: prepare, issue, consume };
}
