// One-machine, multiple-process authority pilot. All workers must use the same
// private local filesystem and route provider callbacks through dispatch().
// A crashed lock is deliberately NOT recovered automatically: the outcome of
// a claimed grant may be unknown and needs operator reconciliation.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { hashHandoffBytes as hash, validHandoffIdentity as identity,
  snapshotHandoffBinding as binding } from "./handoff-binding.mjs";

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DIGEST = /^[0-9a-f]{64}$/;

// A private leaf is insufficient if a parent can be switched to an older
// authority snapshot. /tmp-style sticky directories protect an owned child;
// ordinary group/world-writable ancestors do not.
function verifyAuthorityPath(target, { allowMissing = false, pinned = null, record = null } = {}) {
  const root = path.parse(target).root;
  const components = path.relative(root, target).split(path.sep).filter(Boolean);
  let current = root;
  let stat;
  for (const component of [null, ...components]) {
    if (component !== null) current = path.join(current, component);
    try { stat = fs.lstatSync(current); }
    catch (error) {
      if (allowMissing && error.code === "ENOENT") return null;
      throw error;
    }
    if (!stat.isDirectory() || typeof process.getuid !== "function" ||
        (stat.uid !== 0 && stat.uid !== process.getuid()) ||
        ((stat.mode & 0o022) !== 0 && !(stat.mode & 0o1000))) {
      throw Error("trusted_authority_path_required");
    }
    if (pinned?.has(current) &&
        (pinned.get(current).dev !== stat.dev || pinned.get(current).ino !== stat.ino)) {
      throw Error("authority_path_changed");
    }
    record?.set(current, { dev: stat.dev, ino: stat.ino });
  }
  return stat;
}

function privateDirectory(directory, create = false, pinned = null) {
  if (create) {
    verifyAuthorityPath(path.dirname(directory), { allowMissing: true });
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  const stat = verifyAuthorityPath(directory, { pinned });
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0 ||
      typeof process.getuid !== "function" || stat.uid !== process.getuid()) {
    throw Error("private_authority_directory_required");
  }
}

function syncDirectory(directory) {
  const fd = fs.openSync(directory, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function readRecord(file) {
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid() ||
        stat.size < 2 || stat.size > 2048) throw Error("invalid_authority_record");
    const record = JSON.parse(fs.readFileSync(fd, "utf8"));
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw Error("invalid_authority_record");
    }
    return record;
  } finally { fs.closeSync(fd); }
}

function createExclusive(file, record, directory) {
  const fd = fs.openSync(file, "wx", 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(record) + "\n");
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  syncDirectory(directory);
}

function replaceAtomic(file, record, directory) {
  const temp = `${file}.${randomUUID()}.tmp`;
  createExclusive(temp, record, directory);
  fs.renameSync(temp, file);
  syncDirectory(directory);
}

function hasUncertainTemp(directory, basename) {
  return fs.readdirSync(directory).some(name => name.startsWith(`${basename}.`) && name.endsWith(".tmp"));
}

function freezeDeep(value) {
  const pending = [value];
  while (pending.length) {
    const item = pending.pop();
    if (item && typeof item === "object") {
      pending.push(...Object.values(item));
      Object.freeze(item);
    }
  }
  return value;
}

export function createFileRevocationHandoff({ directory, now = () => Date.now() } = {}) {
  if (typeof directory !== "string" || !path.isAbsolute(directory) ||
      directory !== path.resolve(directory) || typeof now !== "function") {
    throw new TypeError("A trusted absolute directory and host clock are required");
  }
  privateDirectory(directory, true);
  const epochs = path.join(directory, "epochs");
  const grants = path.join(directory, "grants");
  const claimed = path.join(directory, "claimed");
  const outcomes = path.join(directory, "outcomes");
  const lock = path.join(directory, "authority.lock");
  const clockFile = path.join(directory, "clock.json");
  for (const child of [epochs, grants, claimed, outcomes]) privateDirectory(child, true);
  const pinned = new Map();
  for (const child of [directory, epochs, grants, claimed, outcomes]) {
    verifyAuthorityPath(child, { record: pinned });
  }

  function checkDirectories() {
    for (const child of [directory, epochs, grants, claimed, outcomes]) privateDirectory(child, false, pinned);
  }

  function acquire() {
    checkDirectories();
    try { fs.mkdirSync(lock, { mode: 0o700 }); }
    catch (error) {
      if (error.code === "EEXIST") throw Error("authority_busy_or_crashed");
      throw error;
    }
    syncDirectory(directory); // If this fails, leave the lock to fail closed.
  }

  function release() {
    checkDirectories();
    fs.rmdirSync(lock);
    syncDirectory(directory);
  }

  function locked(action) {
    acquire();
    try { return action(); }
    finally { release(); }
  }

  function hostTime() {
    const time = now();
    if (!Number.isSafeInteger(time)) throw Error("host_clock_unavailable");
    if (hasUncertainTemp(directory, "clock.json")) throw Error("uncertain_clock_update");
    const previous = readRecord(clockFile);
    if (previous && (previous.protocol !== "aml-file-authority-clock/1" ||
        !Number.isSafeInteger(previous.time_ms))) throw Error("invalid_authority_clock");
    if (previous && time < previous.time_ms) throw Error("host_clock_rollback");
    replaceAtomic(clockFile, { protocol: "aml-file-authority-clock/1", time_ms: time }, directory);
    return time;
  }

  function issuerHash(tenant, issuer) {
    return hash(canonicalJSONStringify([tenant, issuer]));
  }

  function currentEpoch(key) {
    const file = `${key}.json`;
    if (hasUncertainTemp(epochs, file)) throw Error("uncertain_epoch_update");
    const record = readRecord(path.join(epochs, file));
    if (!record) return 0;
    if (record.protocol !== "aml-file-authority-epoch/1" || record.issuer_sha256 !== key ||
        !Number.isSafeInteger(record.epoch) || record.epoch <= 0) {
      throw Error("invalid_authority_epoch");
    }
    return record.epoch;
  }

  function revokeIssuer({ tenant, issuer } = {}) {
    if (!identity(tenant) || !identity(issuer)) throw new TypeError("Invalid tenant or issuer");
    return locked(() => {
      const key = issuerHash(tenant, issuer);
      const next = currentEpoch(key) + 1;
      if (!Number.isSafeInteger(next)) throw Error("revocation_epoch_exhausted");
      replaceAtomic(path.join(epochs, `${key}.json`), {
        protocol: "aml-file-authority-epoch/1", issuer_sha256: key, epoch: next
      }, epochs);
      return { tenant, issuer, epoch: next };
    });
  }

  function issue(input, { ttlMs = 60_000 } = {}) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > 300_000) {
      throw new TypeError("TTL must be between 1 ms and five minutes");
    }
    const bound = binding(input);
    return locked(() => {
      const issuedAt = hostTime();
      if (!Number.isSafeInteger(issuedAt + ttlMs)) throw Error("host_clock_unavailable");
      const epoch = currentEpoch(issuerHash(bound.context.tenant, bound.context.issuer));
      const grantId = randomUUID();
      createExclusive(path.join(grants, `${grantId}.json`), {
        protocol: "aml-file-authority-grant/1", grant_id: grantId,
        issuer_sha256: issuerHash(bound.context.tenant, bound.context.issuer),
        binding_sha256: bound.sha256, epoch, issued_at_ms: issuedAt,
        expires_at_ms: issuedAt + ttlMs
      }, grants);
      return { grant_id: grantId, binding_sha256: bound.sha256,
        prepared_request_sha256: bound.request.sha256, policy_sha256: bound.policy.sha256 };
    });
  }

  async function dispatch({ grant_id, execute, ...input } = {}) {
    const denied = (status, reason) => ({ status, reason, dispatch_count: 0 });
    if (typeof execute !== "function") return denied("blocked", "missing_host_dispatch");
    if (typeof grant_id !== "string" || !ID.test(grant_id)) return denied("blocked", "invalid_grant_id");
    let bound;
    try { bound = binding(input); }
    catch { return denied("blocked", "invalid_authority_input"); }
    let held = false, invoked = false, callbackThrew = false, response, decision;
    const idempotencyKey = hash(canonicalJSONStringify([bound.context.tenant, grant_id]));
    try {
      acquire();
      held = true;
      const record = readRecord(path.join(grants, `${grant_id}.json`));
      if (!record) decision = denied("blocked", "grant_missing");
      else if (record.protocol !== "aml-file-authority-grant/1" || record.grant_id !== grant_id ||
          !DIGEST.test(record.binding_sha256) || !DIGEST.test(record.issuer_sha256) ||
          !Number.isSafeInteger(record.epoch) || record.epoch < 0 ||
          !Number.isSafeInteger(record.issued_at_ms) || !Number.isSafeInteger(record.expires_at_ms) ||
          record.issued_at_ms >= record.expires_at_ms) {
        decision = denied("indeterminate", "invalid_grant_record");
      } else if (record.binding_sha256 !== bound.sha256 ||
          record.issuer_sha256 !== issuerHash(bound.context.tenant, bound.context.issuer)) {
        decision = denied("blocked", "binding_mismatch");
      } else {
        const claimFile = path.join(claimed, `${grant_id}.json`);
        if (fs.existsSync(claimFile)) decision = denied("blocked", "grant_spent_or_uncertain");
        else {
          const time = hostTime();
          if (time < record.issued_at_ms || time >= record.expires_at_ms) {
            decision = denied("blocked", "grant_expired_or_clock_invalid");
          } else if (currentEpoch(record.issuer_sha256) !== record.epoch) {
            decision = denied("blocked", "issuer_revoked");
          } else {
            // This marker is durable before callback invocation. A crash after
            // the marker leaves the grant spent and the global lock stranded.
            createExclusive(claimFile, { protocol: "aml-file-authority-claim/1",
              grant_id, binding_sha256: bound.sha256,
              idempotency_key_sha256: idempotencyKey }, claimed);
            try {
              invoked = true;
              response = execute(freezeDeep(JSON.parse(bound.request.bytes)), { idempotencyKey });
            } catch { callbackThrew = true; }
          }
        }
      }
    } catch (error) {
      decision = invoked ? { status: "outcome_unknown", reason: "authority_or_callback_error", dispatch_count: 1 } :
        denied("indeterminate", error.message === "authority_busy_or_crashed" ? error.message :
          "authority_store_unavailable");
    } finally {
      if (held) {
        try { release(); }
        catch { decision = invoked ? { status: "outcome_unknown", reason: "lock_release_failed", dispatch_count: 1 } :
          denied("indeterminate", "lock_release_failed"); }
      }
    }
    if (decision) return decision;
    let outcome;
    try {
      if (callbackThrew) throw Error("callback_threw");
      const result = await response;
      outcome = { status: "returned", reason: "callback_returned", dispatch_count: 1, result };
    } catch {
      outcome = { status: "outcome_unknown", reason: "callback_error", dispatch_count: 1 };
    }
    try {
      checkDirectories();
      createExclusive(path.join(outcomes, `${grant_id}.json`), {
        protocol: "aml-file-authority-outcome/1", grant_id, binding_sha256: bound.sha256,
        status: outcome.status, reason: outcome.reason
      }, outcomes);
    } catch {
      return { status: "outcome_unknown", reason: "outcome_record_unavailable", dispatch_count: 1 };
    }
    return outcome;
  }

  return { issue, revokeIssuer, dispatch };
}
