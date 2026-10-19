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
const CLAIM_V1 = "aml-file-authority-external-claim/1";
const CLAIM_V2 = "aml-file-authority-external-claim/2";
const AUTHORITY_MODES = ["local", "claim-anchored", "epoch-anchored",
  "checkpoint-anchored", "checkpoint-claim-anchored"];

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

const DECISION_COLLECTIONS = [
  ["epochs", /^[0-9a-f]{64}\.json$/],
  ["grants", /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json$/],
  ["operations", /^[0-9a-f]{64}\.json$/],
  ["claimed", /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json$/]
];

function decisionState(directory, overrides = [], includeMode = false) {
  const replacements = new Map(overrides.map(({ collection, name, record }) =>
    [`${collection}/${name}`, record]));
  const entries = [], counts = {};
  for (const [collection, pattern] of DECISION_COLLECTIONS) {
    const child = path.join(directory, collection);
    const names = fs.readdirSync(child);
    if (names.some(name => !pattern.test(name))) throw Error("unexpected_authority_state_entry");
    for (const key of replacements.keys()) {
      if (key.startsWith(`${collection}/`)) names.push(key.slice(collection.length + 1));
    }
    const unique = [...new Set(names)].sort();
    counts[collection] = unique.length;
    for (const name of unique) {
      if (!pattern.test(name)) throw Error("unexpected_authority_state_entry");
      const key = `${collection}/${name}`;
      const record = replacements.has(key) ? replacements.get(key) :
        readRecord(path.join(child, name));
      if (!record) throw Error("authority_state_record_unavailable");
      entries.push([key, hash(canonicalJSONStringify(record))]);
    }
  }
  if (includeMode) {
    const mode = readRecord(path.join(directory, "authority-mode.json"));
    if (!mode) throw Error("authority_mode_unavailable");
    entries.push(["authority-mode.json", hash(canonicalJSONStringify(mode))]);
  }
  return { digest: hash(canonicalJSONStringify(entries)), counts };
}

function nestedDirectories(first, second) {
  const relative = path.relative(first, second);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative));
}

function checkpointRecord(value) {
  const v1 = value?.protocol === "aml-file-authority-checkpoint/1";
  const v2 = value?.protocol === "aml-file-authority-checkpoint/2";
  const v3 = value?.protocol === "aml-file-authority-checkpoint/3";
  return (v1 || v2 || v3) &&
    ID.test(value.store_id) && Number.isSafeInteger(value.sequence) && value.sequence >= 0 &&
    DIGEST.test(value.head_sha256) &&
    (v1 ? Object.keys(value).sort().join("|") === "head_sha256|protocol|sequence|store_id" :
      DIGEST.test(value.state_sha256) &&
      Object.keys(value).sort().join("|") ===
        "head_sha256|protocol|sequence|state_sha256|store_id");
}

function claimReconciliation(directory) {
  const claimed = path.join(directory, "claimed");
  const outcomes = path.join(directory, "outcomes");
  const names = fs.readdirSync(claimed).sort();
  const outcomeNames = fs.readdirSync(outcomes).sort();
  const pattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json$/;
  const candidates = [], issues = [];
  const counts = { claims: names.length, outcomes: outcomeNames.length,
    returned: 0, missing_outcome: 0, unknown_outcome: 0 };
  const claimNames = new Set(names);
  const outcomeNamesSet = new Set(outcomeNames);
  for (const name of names) {
    if (!pattern.test(name)) {
      issues.push({ collection: "claimed", problem: "unexpected_filename" });
      continue;
    }
    const grantId = name.slice(0, -5);
    let claim, grant, outcome, grantUnreadable = false;
    try { claim = readRecord(path.join(claimed, name)); }
    catch { issues.push({ grant_id: grantId, problem: "claim_unreadable" }); continue; }
    if (claim?.protocol !== "aml-file-authority-claim/1" ||
        claim.grant_id !== grantId || !DIGEST.test(claim.binding_sha256) ||
        !DIGEST.test(claim.idempotency_key_sha256)) {
      issues.push({ grant_id: grantId, problem: "claim_invalid" });
      continue;
    }
    try { grant = readRecord(path.join(directory, "grants", name)); }
    catch { issues.push({ grant_id: grantId, problem: "grant_unreadable" });
      grantUnreadable = true; }
    if (!grantUnreadable && (!grant || grant.protocol !== "aml-file-authority-grant/1" ||
        grant.grant_id !== grantId || grant.binding_sha256 !== claim.binding_sha256 ||
        (grant.operation_sha256 !== undefined && !DIGEST.test(grant.operation_sha256)))) {
      issues.push({ grant_id: grantId, problem: "grant_missing_or_mismatch" });
    }
    if (grant?.operation_sha256 && DIGEST.test(grant.operation_sha256)) {
      let operation, operationUnreadable = false;
      try { operation = readRecord(path.join(directory, "operations",
        `${grant.operation_sha256}.json`)); }
      catch { issues.push({ grant_id: grantId, problem: "operation_unreadable" });
        operationUnreadable = true; }
      if (!operationUnreadable && (!operation ||
          operation.protocol !== "aml-file-authority-operation/1" ||
          operation.operation_sha256 !== grant.operation_sha256 ||
          operation.grant_id !== grantId ||
          operation.binding_sha256 !== claim.binding_sha256)) {
        issues.push({ grant_id: grantId, problem: "operation_missing_or_mismatch" });
      }
    }
    if (outcomeNamesSet.has(name)) {
      try { outcome = readRecord(path.join(outcomes, name)); }
      catch { issues.push({ grant_id: grantId, problem: "outcome_unreadable" }); continue; }
      if (!outcome || outcome.protocol !== "aml-file-authority-outcome/1" ||
          outcome.grant_id !== grantId ||
          outcome.binding_sha256 !== claim.binding_sha256 ||
          !["returned", "outcome_unknown"].includes(outcome.status) ||
          typeof outcome.reason !== "string") {
        issues.push({ grant_id: grantId, problem: "outcome_invalid_or_mismatch" });
        continue;
      }
    }
    if (!outcome) counts.missing_outcome++;
    else if (outcome.status === "outcome_unknown") counts.unknown_outcome++;
    else counts.returned++;
    if (!outcome || outcome.status === "outcome_unknown") {
      candidates.push({ grant_id: grantId,
        operation_sha256: DIGEST.test(grant?.operation_sha256) ?
          grant.operation_sha256 : null,
        idempotency_key_sha256: claim.idempotency_key_sha256,
        local_outcome: outcome?.status ?? "missing" });
    }
  }
  for (const name of outcomeNames) {
    if (!pattern.test(name)) {
      issues.push({ collection: "outcomes", problem: "unexpected_filename" });
    } else if (!claimNames.has(name)) {
      issues.push({ grant_id: name.slice(0, -5), problem: "outcome_without_claim" });
    }
  }
  return { status: issues.length ? "invalid_records" : candidates.length ?
    "provider_review_needed" : "no_unresolved_local_claims",
  counts, candidates, issues };
}

// One-machine example of the host's independent monotonic checkpoint store.
// Keep this directory under a separate backup/retention domain. Restoring
// both directories together can still replay an older authority snapshot.
export function createFileAuthorityAnchor({ directory, create = true } = {}) {
  if (typeof directory !== "string" || !path.isAbsolute(directory) ||
      directory !== path.resolve(directory) || typeof create !== "boolean") {
    throw new TypeError("trusted_anchor_path_required");
  }
  privateDirectory(directory, create);
  const file = path.join(directory, "checkpoint.json");
  const lock = path.join(directory, "anchor.lock");
  const pinned = new Map();
  verifyAuthorityPath(directory, { record: pinned });
  const check = () => privateDirectory(directory, false, pinned);
  const read = () => { check();
    if (hasUncertainTemp(directory, "checkpoint.json")) throw Error("uncertain_anchor_update");
    return readRecord(file);
  };
  function compareAndSwap(expected, next) {
    check();
    try { fs.mkdirSync(lock, { mode: 0o700 }); }
    catch (error) {
      if (error.code === "EEXIST") throw Error("anchor_busy_or_crashed");
      throw error;
    }
    syncDirectory(directory);
    try {
      const prior = read();
      if (canonicalJSONStringify(prior) !== canonicalJSONStringify(expected)) return false;
      if (!next || !["aml-file-authority-checkpoint/1",
        "aml-file-authority-checkpoint/2",
        "aml-file-authority-checkpoint/3"].includes(next.protocol) ||
          !ID.test(next.store_id) || !Number.isSafeInteger(next.sequence) ||
          !DIGEST.test(next.head_sha256) ||
          (next.protocol !== "aml-file-authority-checkpoint/1" &&
            !DIGEST.test(next.state_sha256)) ||
          next.sequence !== (prior ? prior.sequence + 1 : 0) ||
          (prior && (next.store_id !== prior.store_id ||
            next.protocol !== prior.protocol))) throw Error("invalid_anchor_transition");
      if (prior) replaceAtomic(file, next, directory);
      else createExclusive(file, next, directory);
      return true;
    } finally { check(); fs.rmdirSync(lock); syncDirectory(directory); }
  }
  return { directory, read, compareAndSwap };
}

// A non-atomic, read-only operator observation. It never takes/removes the
// authority lock or changes a checkpoint; live workers may change the view.
export function inspectFileRevocationHandoff({ directory, anchor = null } = {}) {
  if (typeof directory !== "string" || !path.isAbsolute(directory) ||
      directory !== path.resolve(directory) ||
      (anchor !== null && typeof anchor.read !== "function")) {
    throw new TypeError("A trusted absolute directory and optional readable anchor are required");
  }
  privateDirectory(directory);
  const children = [directory, ...[...DECISION_COLLECTIONS.map(([name]) => name),
    "outcomes"].map(name => path.join(directory, name))];
  const pinned = new Map();
  for (const child of children) {
    privateDirectory(child);
    verifyAuthorityPath(child, { record: pinned });
  }
  const reasons = [];
  const lock = path.join(directory, "authority.lock");
  const observeLock = () => {
    try { fs.lstatSync(lock); privateDirectory(lock); return "present"; }
    catch (error) { return error.code === "ENOENT" ? "absent" : "invalid"; }
  };
  const lockStatus = observeLock();
  if (lockStatus !== "absent") reasons.push(lockStatus === "present" ?
    "authority_lock_present" : "invalid_authority_lock");
  let anchorLock = "not_applicable";
  let observeAnchorLock = null;
  if (typeof anchor?.directory === "string" && path.isAbsolute(anchor.directory)) {
    const anchorLockFile = path.join(anchor.directory, "anchor.lock");
    observeAnchorLock = () => {
      try { fs.lstatSync(anchorLockFile); privateDirectory(anchorLockFile);
        return "present"; }
      catch (error) { return error.code === "ENOENT" ? "absent" : "invalid"; }
    };
    anchorLock = observeAnchorLock();
    if (anchorLock !== "absent") reasons.push(anchorLock === "present" ?
      "external_anchor_lock_present" : "invalid_external_anchor_lock");
  }

  let local = null, localRead = null, external = null, counts = null, observedDigest = null;
  let localReadable = true, externalReadable = true;
  const modeFile = path.join(directory, "authority-mode.json");
  let modeRead = null, modeRecord = null, modeStatus = "missing", modeReadable = true;
  if (hasUncertainTemp(directory, "authority-mode.json")) reasons.push("uncertain_authority_mode");
  try { modeRead = readRecord(modeFile); modeRecord = modeRead; }
  catch { reasons.push("authority_mode_unreadable"); modeReadable = false;
    modeStatus = "unreadable"; }
  if (modeRecord) {
    if (modeRecord.protocol !== "aml-file-authority-mode/1" ||
        !AUTHORITY_MODES.includes(modeRecord.mode)) {
      reasons.push("authority_mode_invalid");
      modeRecord = null;
      modeStatus = "invalid";
    } else modeStatus = "valid";
  }
  const checkpointFile = path.join(directory, "checkpoint.json");
  if (hasUncertainTemp(directory, "checkpoint.json")) reasons.push("uncertain_authority_checkpoint");
  try { localRead = readRecord(checkpointFile); local = localRead; }
  catch { reasons.push("local_checkpoint_unreadable"); localReadable = false; }
  if (local && !checkpointRecord(local)) {
    reasons.push("local_checkpoint_invalid");
    local = null;
  }
  if (anchor) {
    if (anchor.directory && (nestedDirectories(directory, anchor.directory) ||
        nestedDirectories(anchor.directory, directory))) reasons.push("anchor_not_independent");
    try {
      external = anchor.read();
      if (external?.then) throw Error("synchronous_authority_anchor_required");
    } catch { reasons.push("external_checkpoint_unavailable"); external = null;
      externalReadable = false; }
    if (external && !checkpointRecord(external)) {
      reasons.push("external_checkpoint_invalid");
      external = null;
      externalReadable = false;
    }
    if (!localRead && localReadable) reasons.push("local_checkpoint_missing");
    if (!external && externalReadable) reasons.push("external_checkpoint_missing");
  } else if (local) reasons.push("authority_anchor_not_supplied");

  let comparison = anchor ? "unavailable" : "not_configured";
  if (local && external) {
    comparison = canonicalJSONStringify(local) === canonicalJSONStringify(external) ?
      "match" : "mismatch";
    if (comparison === "mismatch") reasons.push("checkpoint_mismatch");
  }
  let committedState = local && local.protocol !== "aml-file-authority-checkpoint/1" ?
    "unavailable" : "not_committed";
  try {
    ({ counts, digest: observedDigest } = decisionState(directory, [],
      local?.protocol === "aml-file-authority-checkpoint/3"));
    if (local && local.protocol !== "aml-file-authority-checkpoint/1") {
      committedState = observedDigest === local.state_sha256 ? "match" : "mismatch";
      if (committedState === "mismatch") reasons.push("committed_state_mismatch");
    }
  } catch { reasons.push("committed_state_unreadable"); }
  let reconciliation = null;
  try {
    reconciliation = claimReconciliation(directory);
    if (reconciliation.issues.length) reasons.push("reconciliation_records_invalid");
    if (reconciliation.candidates.length) reasons.push("claims_need_provider_review");
  } catch { reasons.push("reconciliation_unavailable"); }
  // A genuinely fresh directory and an older empty store with a deleted mode
  // are indistinguishable from a read-only scan. Neither is verified state.
  if (modeStatus === "missing") reasons.push("authority_mode_missing");
  if (modeRecord && ((modeRecord.mode.startsWith("checkpoint-") && !local) ||
      (!modeRecord.mode.startsWith("checkpoint-") && local) ||
      (anchor && !modeRecord.mode.startsWith("checkpoint-")))) {
    reasons.push("authority_mode_checkpoint_mismatch");
  }

  // A changed checkpoint during the scan makes the snapshot unsuitable for
  // reassurance, even if the first two reads happened to match.
  if (localReadable) {
    try {
      if (canonicalJSONStringify(readRecord(checkpointFile)) !== canonicalJSONStringify(localRead)) {
        reasons.push("local_checkpoint_changed_during_inspection");
      }
    } catch { reasons.push("local_checkpoint_changed_during_inspection"); }
  }
  if (anchor && externalReadable) {
    try {
      const again = anchor.read();
      if (again?.then || canonicalJSONStringify(again) !== canonicalJSONStringify(external)) {
        reasons.push("external_checkpoint_changed_during_inspection");
      }
    } catch { reasons.push("external_checkpoint_changed_during_inspection"); }
  }
  if (modeReadable) {
    try {
      if (canonicalJSONStringify(readRecord(modeFile)) !== canonicalJSONStringify(modeRead)) {
        reasons.push("authority_mode_changed_during_inspection");
      }
    } catch { reasons.push("authority_mode_changed_during_inspection"); }
  }
  try { for (const child of children) privateDirectory(child, false, pinned); }
  catch { reasons.push("authority_path_changed_during_inspection"); }
  if (observeLock() !== lockStatus) reasons.push("authority_lock_changed_during_inspection");
  if (observeAnchorLock && observeAnchorLock() !== anchorLock) {
    reasons.push("external_anchor_lock_changed_during_inspection");
  }
  return {
    protocol: "aml-file-authority-inspection/1",
    status: reasons.length ? "needs_reconciliation" : "observed_consistent",
    reasons, lock: lockStatus, anchor_lock: anchorLock, mode: local?.protocol ??
      (localRead || !localReadable || anchor ? "unknown" : "unanchored"),
    authority_mode: { status: modeStatus, record: modeRecord },
    checkpoints: { local, external, comparison },
    reconciliation,
    committed_state: { comparison: committedState, observed_sha256: observedDigest,
      includes_authority_mode: local?.protocol === "aml-file-authority-checkpoint/3", counts }
  };
}

export function createFileRevocationHandoff({ directory, now = () => Date.now(), anchor,
  claimOnce = null, epochAnchor = null } = {}) {
  if (typeof directory !== "string" || !path.isAbsolute(directory) ||
      directory !== path.resolve(directory) || typeof now !== "function" ||
      (anchor !== undefined && (!anchor || typeof anchor.read !== "function" ||
        typeof anchor.compareAndSwap !== "function")) ||
      (claimOnce !== null && typeof claimOnce !== "function") ||
      (epochAnchor !== null && (typeof epochAnchor !== "object" ||
        typeof epochAnchor.claimOnce !== "function" ||
        typeof epochAnchor.advanceEpoch !== "function" || claimOnce !== null ||
        anchor !== undefined))) {
    throw new TypeError("A trusted directory, clock, and optional atomic host anchor are required; incompatible anchor options");
  }
  if (anchor?.directory && (nestedDirectories(directory, anchor.directory) ||
      nestedDirectories(anchor.directory, directory))) {
    throw new TypeError("independent_anchor_directory_required");
  }
  const externalClaim = epochAnchor ? epochAnchor.claimOnce.bind(epochAnchor) : claimOnce;
  const externalAdvance = epochAnchor?.advanceEpoch.bind(epochAnchor);
  const claimProtocol = epochAnchor ? CLAIM_V2 : claimOnce ? CLAIM_V1 : null;
  privateDirectory(directory, true);
  const epochs = path.join(directory, "epochs");
  const grants = path.join(directory, "grants");
  const operations = path.join(directory, "operations");
  const claimed = path.join(directory, "claimed");
  const outcomes = path.join(directory, "outcomes");
  const lock = path.join(directory, "authority.lock");
  const clockFile = path.join(directory, "clock.json");
  const modeFile = path.join(directory, "authority-mode.json");
  const checkpointFile = path.join(directory, "checkpoint.json");
  const authorityMode = epochAnchor ? "epoch-anchored" : anchor ?
    claimOnce ? "checkpoint-claim-anchored" : "checkpoint-anchored" :
    claimOnce ? "claim-anchored" : "local";
  for (const child of [epochs, grants, operations, claimed, outcomes]) privateDirectory(child, true);
  const pinned = new Map();
  for (const child of [directory, epochs, grants, operations, claimed, outcomes]) {
    verifyAuthorityPath(child, { record: pinned });
  }

  // Checkpoints 2 and 3 commit to durable decision files; version 3 binds
  // the mode too. The host clock and outcomes have a separate lifecycle.
  const stateDigest = (overrides = [], includeMode = false) =>
    decisionState(directory, overrides, includeMode).digest;

  function checkDirectories() {
    for (const child of [directory, epochs, grants, operations, claimed, outcomes]) {
      privateDirectory(child, false, pinned);
    }
  }

  function checkMode({ initialize = true } = {}) {
    const record = readRecord(modeFile);
    if (!record) {
      // A missing mode in an existing store may be a rollback or lost mode
      // record. Never infer a weaker mode from the current worker's config.
      if (!initialize || fs.existsSync(clockFile) || fs.existsSync(checkpointFile) ||
          [epochs, grants, operations, claimed, outcomes]
            .some(child => fs.readdirSync(child).length !== 0)) {
        throw Error("authority_mode_unavailable");
      }
      createExclusive(modeFile, {
        protocol: "aml-file-authority-mode/1", mode: authorityMode
      }, directory);
    } else if (record.protocol !== "aml-file-authority-mode/1" ||
        !AUTHORITY_MODES.includes(record.mode)) {
      throw Error("invalid_authority_mode");
    } else if (record.mode !== authorityMode) {
      throw Error("authority_mode_mismatch");
    }
  }

  function externalState() {
    const value = anchor.read();
    if (value?.then) throw Error("synchronous_authority_anchor_required");
    return value;
  }

  function checkCheckpoint() {
    if (hasUncertainTemp(directory, "checkpoint.json")) throw Error("uncertain_authority_checkpoint");
    const local = readRecord(checkpointFile);
    if (!anchor) {
      if (local) throw Error("authority_anchor_required");
      return null;
    }
    if (!checkpointRecord(local) ||
        canonicalJSONStringify(externalState()) !== canonicalJSONStringify(local)) {
      throw Error("authority_anchor_mismatch");
    }
    if (local.protocol !== "aml-file-authority-checkpoint/1" &&
        stateDigest([], local.protocol === "aml-file-authority-checkpoint/3") !==
          local.state_sha256) throw Error("authority_state_mismatch");
    return local;
  }

  // Initialize only on an empty authority. An existing unanchored history
  // cannot acquire a trustworthy external past by merely adding an anchor.
  if (anchor) {
    checkDirectories();
    try { fs.mkdirSync(lock, { mode: 0o700 }); }
    catch (error) {
      if (error.code === "EEXIST") throw Error("authority_busy_or_crashed");
      throw error;
    }
    try {
      checkMode();
      if (readRecord(checkpointFile)) checkCheckpoint();
      else {
        if (externalState() !== null || fs.existsSync(clockFile) ||
            [epochs, grants, operations, claimed, outcomes].some(child =>
              fs.readdirSync(child).length !== 0)) throw Error("anchor_requires_empty_authority");
        const store_id = randomUUID();
        const initial = { protocol: "aml-file-authority-checkpoint/3", store_id,
          sequence: 0, head_sha256: hash(canonicalJSONStringify(["genesis", store_id])),
          state_sha256: stateDigest([], true) };
        if (anchor.compareAndSwap(null, Object.freeze(initial)) !== true ||
            canonicalJSONStringify(externalState()) !== canonicalJSONStringify(initial)) {
          throw Error("authority_anchor_unavailable");
        }
        createExclusive(checkpointFile, initial, directory);
      }
    } finally { fs.rmdirSync(lock); syncDirectory(directory); }
  } else if (readRecord(checkpointFile)) {
    throw Error("authority_anchor_required");
  }

  function anchoredWrite(kind, key, record, write, overrides = []) {
    if (!anchor) return write();
    const previous = checkCheckpoint();
    if (!Number.isSafeInteger(previous.sequence + 1)) throw Error("anchor_sequence_exhausted");
    const next = { protocol: previous.protocol, store_id: previous.store_id,
      sequence: previous.sequence + 1,
      head_sha256: hash(canonicalJSONStringify([previous.head_sha256, kind, key,
        hash(canonicalJSONStringify(record))])),
      ...(previous.protocol !== "aml-file-authority-checkpoint/1" ?
        { state_sha256: stateDigest(overrides,
          previous.protocol === "aml-file-authority-checkpoint/3") } : {}) };
    if (anchor.compareAndSwap(Object.freeze({ ...previous }), Object.freeze({ ...next })) !== true ||
        canonicalJSONStringify(externalState()) !== canonicalJSONStringify(next)) {
      throw Error("authority_anchor_unavailable");
    }
    const result = write();
    if (next.state_sha256 &&
        stateDigest([], next.protocol === "aml-file-authority-checkpoint/3") !==
          next.state_sha256) {
      throw Error("authority_state_mismatch");
    }
    replaceAtomic(checkpointFile, next, directory);
    return result;
  }

  function acquire() {
    checkDirectories();
    checkCheckpoint();
    try { fs.mkdirSync(lock, { mode: 0o700 }); }
    catch (error) {
      if (error.code === "EEXIST") throw Error("authority_busy_or_crashed");
      throw error;
    }
    syncDirectory(directory); // If this fails, leave the lock to fail closed.
    try { checkCheckpoint(); checkMode(); }
    catch (error) {
      // A mismatched worker must not strand the legitimate workers' lock.
      // A failed release still fails closed for everyone.
      release();
      throw error;
    }
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
    if (epochAnchor) throw Error("anchored_revocation_required");
    if (!identity(tenant) || !identity(issuer)) throw new TypeError("Invalid tenant or issuer");
    return locked(() => {
      const key = issuerHash(tenant, issuer);
      const next = currentEpoch(key) + 1;
      if (!Number.isSafeInteger(next)) throw Error("revocation_epoch_exhausted");
      const record = {
        protocol: "aml-file-authority-epoch/1", issuer_sha256: key, epoch: next
      };
      anchoredWrite("revoke", key, record, () =>
        replaceAtomic(path.join(epochs, `${key}.json`), record, epochs),
      [{ collection: "epochs", name: `${key}.json`, record }]);
      return { tenant, issuer, epoch: next };
    });
  }

  // The external epoch CAS and claim CAS must share one linearizable host
  // store. Keep the local lock stranded on any uncertain or partial advance;
  // an operator must reconcile it before this local state can be reused.
  async function revokeIssuerAnchored({ tenant, issuer } = {}) {
    if (!epochAnchor) throw Error("epoch_anchor_required");
    if (!identity(tenant) || !identity(issuer)) throw new TypeError("Invalid tenant or issuer");
    let held = false, retainLock = false;
    try {
      acquire();
      held = true;
      retainLock = true;
      const key = issuerHash(tenant, issuer);
      const expected = currentEpoch(key);
      const next = expected + 1;
      if (!Number.isSafeInteger(next)) throw Error("revocation_epoch_exhausted");
      let result;
      try {
        result = await externalAdvance(Object.freeze({
          protocol: "aml-file-authority-external-epoch/1",
          issuer_sha256: key, expected_epoch: expected, next_epoch: next
        }));
      } catch { throw Error("external_epoch_unavailable"); }
      if (result === false) throw Error("external_epoch_mismatch");
      if (result !== true) throw Error("external_epoch_unavailable");
      checkDirectories();
      checkMode({ initialize: false });
      if (currentEpoch(key) !== expected) throw Error("authority_epoch_changed");
      replaceAtomic(path.join(epochs, `${key}.json`), {
        protocol: "aml-file-authority-epoch/1", issuer_sha256: key, epoch: next
      }, epochs);
      retainLock = false;
      return { tenant, issuer, epoch: next };
    } finally {
      if (held && !retainLock) release();
    }
  }

  // Observe under the same lock used for revoke and issue. A host can await
  // authenticated approval, then condition issuance on this observed epoch.
  function observeIssuer({ tenant, issuer } = {}) {
    if (!identity(tenant) || !identity(issuer)) throw new TypeError("Invalid tenant or issuer");
    return locked(() => ({ epoch: currentEpoch(issuerHash(tenant, issuer)) }));
  }

  function issue(input, { ttlMs = 60_000, expectedEpoch, operationId } = {}) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > 300_000) {
      throw new TypeError("TTL must be between 1 ms and five minutes");
    }
    if (expectedEpoch !== undefined && (!Number.isSafeInteger(expectedEpoch) || expectedEpoch < 0)) {
      throw new TypeError("Invalid expected issuer epoch");
    }
    if (operationId !== undefined && !identity(operationId)) {
      throw new TypeError("Invalid host operation ID");
    }
    const bound = binding(input);
    return locked(() => {
      const issuer = issuerHash(bound.context.tenant, bound.context.issuer);
      const epoch = currentEpoch(issuer);
      if (expectedEpoch !== undefined && epoch !== expectedEpoch) throw Error("issuer_revoked");
      const issuedAt = hostTime();
      if (!Number.isSafeInteger(issuedAt + ttlMs)) throw Error("host_clock_unavailable");
      const operationHash = operationId === undefined ? null : hash(canonicalJSONStringify([
        bound.context.tenant, bound.context.issuer, operationId
      ]));
      if (operationHash) {
        const previous = readRecord(path.join(operations, `${operationHash}.json`));
        if (previous) {
          if (previous.protocol === "aml-file-authority-operation/1" &&
              previous.operation_sha256 === operationHash &&
              DIGEST.test(previous.binding_sha256) && previous.binding_sha256 !== bound.sha256) {
            throw Error("operation_payload_mismatch");
          }
          throw Error("operation_already_claimed");
        }
      }
      const grantId = randomUUID();
      const operationRecord = operationHash ? {
          protocol: "aml-file-authority-operation/1", operation_sha256: operationHash,
          grant_id: grantId, issuer_sha256: issuer, binding_sha256: bound.sha256,
          epoch
        } : null;
      const grantRecord = {
        protocol: "aml-file-authority-grant/1", grant_id: grantId,
        issuer_sha256: issuer,
        binding_sha256: bound.sha256, epoch, issued_at_ms: issuedAt,
        expires_at_ms: issuedAt + ttlMs,
        ...(claimProtocol ? { required_claim_protocol: claimProtocol } : {}),
        ...(operationHash ? { operation_sha256: operationHash } : {})
      };
      anchoredWrite("issue", grantId, { operation: operationRecord, grant: grantRecord }, () => {
        if (operationHash) {
          // Spend the host intent before the grant. A crash here can lose an
          // action, but it cannot send it twice on this preserved store.
          createExclusive(path.join(operations, `${operationHash}.json`),
            operationRecord, operations);
        }
        createExclusive(path.join(grants, `${grantId}.json`), grantRecord, grants);
      }, [...(operationHash ? [{ collection: "operations", name: `${operationHash}.json`,
        record: operationRecord }] : []),
      { collection: "grants", name: `${grantId}.json`, record: grantRecord }]);
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
          (record.operation_sha256 !== undefined && !DIGEST.test(record.operation_sha256)) ||
          (record.required_claim_protocol !== undefined &&
            record.required_claim_protocol !== CLAIM_V1 &&
            record.required_claim_protocol !== CLAIM_V2) ||
          !Number.isSafeInteger(record.epoch) || record.epoch < 0 ||
          !Number.isSafeInteger(record.issued_at_ms) || !Number.isSafeInteger(record.expires_at_ms) ||
          record.issued_at_ms >= record.expires_at_ms) {
        decision = denied("indeterminate", "invalid_grant_record");
      } else if (record.binding_sha256 !== bound.sha256 ||
          record.issuer_sha256 !== issuerHash(bound.context.tenant, bound.context.issuer)) {
        decision = denied("blocked", "binding_mismatch");
      } else if (record.required_claim_protocol && record.required_claim_protocol !== claimProtocol) {
        decision = denied("indeterminate", "required_anchor_unavailable");
      } else if (record.operation_sha256 && !operationMatches(record)) {
        decision = denied("indeterminate", "operation_record_unavailable");
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
            const claimRecord = { protocol: "aml-file-authority-claim/1",
              grant_id, binding_sha256: bound.sha256,
              idempotency_key_sha256: idempotencyKey };
            anchoredWrite("claim", grant_id, claimRecord, () =>
              createExclusive(claimFile, claimRecord, claimed),
            [{ collection: "claimed", name: `${grant_id}.json`, record: claimRecord }]);
            if (externalClaim) {
              // Keep the local lock across an optional asynchronous CAS. The
              // host anchor must commit before returning exactly true; a
              // restored local snapshot cannot erase that separate claim.
              try {
                const result = await externalClaim(Object.freeze({
                  protocol: claimProtocol,
                  // An operation-backed grant keeps the same host intent key
                  // even if a restored local snapshot mints a different grant.
                  claim_key_sha256: record.operation_sha256 ?? idempotencyKey,
                  binding_sha256: bound.sha256,
                  ...(epochAnchor ? { issuer_sha256: record.issuer_sha256,
                    epoch: record.epoch } : {})
                }));
                if (result === false) decision = denied("blocked", epochAnchor ?
                  "external_claim_or_epoch_rejected" : "external_claim_spent");
                else if (result !== true) decision = denied("indeterminate", "external_claim_unavailable");
              } catch { decision = denied("indeterminate", "external_claim_unavailable"); }
              if (!decision) {
                // An awaited host claim can outlive the grant or allow an
                // authority path replacement. Recheck immediately before the
                // callback, still under the lock and with the claim spent.
                checkDirectories();
                checkMode({ initialize: false });
                checkCheckpoint();
                if (record.operation_sha256 && !operationMatches(record)) {
                  decision = denied("indeterminate", "operation_record_unavailable");
                } else {
                  const postClaimTime = hostTime();
                  if (postClaimTime < record.issued_at_ms || postClaimTime >= record.expires_at_ms) {
                    decision = denied("blocked", "grant_expired_or_clock_invalid");
                  } else if (currentEpoch(record.issuer_sha256) !== record.epoch) {
                    decision = denied("blocked", "issuer_revoked");
                  }
                }
              }
            }
            if (!decision) {
              try {
                invoked = true;
                response = execute(freezeDeep(JSON.parse(bound.request.bytes)), { idempotencyKey });
              } catch { callbackThrew = true; }
            }
          }
        }
      }
    } catch (error) {
      decision = invoked ? { status: "outcome_unknown", reason: "authority_or_callback_error", dispatch_count: 1 } :
        denied("indeterminate", ["authority_busy_or_crashed", "authority_mode_mismatch"].includes(error.message) ? error.message :
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

  function operationMatches(record) {
    const saved = readRecord(path.join(operations, `${record.operation_sha256}.json`));
    return saved && saved.protocol === "aml-file-authority-operation/1" &&
      saved.operation_sha256 === record.operation_sha256 && saved.grant_id === record.grant_id &&
      saved.issuer_sha256 === record.issuer_sha256 &&
      saved.binding_sha256 === record.binding_sha256 && saved.epoch === record.epoch;
  }

  return { observeIssuer, issue, revokeIssuer, revokeIssuerAnchored, dispatch };
}
