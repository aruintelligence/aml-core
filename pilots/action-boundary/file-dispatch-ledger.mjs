// Host-owned, local-filesystem dispatch claim. This is a fail-closed pilot,
// not a transactional outbox or a guarantee about external side effects.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const hex = value => crypto.createHash("sha256").update(value).digest("hex");
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const DIGEST = /^[a-f0-9]{64}$/;
function freezeDeep(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function privateDirectory(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw new TypeError("absolute_directory_required");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = fs.lstatSync(directory);
  if (!info.isDirectory() || (info.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" && info.uid !== process.getuid())) {
    throw new Error("private_directory_required");
  }
  return directory;
}

function syncDirectory(directory) {
  const fd = fs.openSync(directory, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function createExclusive(file, record, directory) {
  let fd;
  try { fd = fs.openSync(file, "wx", 0o600); }
  catch (error) {
    if (error.code === "EEXIST") return false;
    throw error;
  }
  try {
    fs.writeFileSync(fd, JSON.stringify(record) + "\n");
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  syncDirectory(directory);
  return true;
}

function readRecord(file) {
  try {
    const info = fs.lstatSync(file);
    if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > 2048) return null;
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch { return null; }
}

export function createFileDispatchLedger({ directory } = {}) {
  const root = privateDirectory(directory);
  const input = (operationId, proposal) => {
    if (typeof operationId !== "string" || !ID.test(operationId)) throw new TypeError("invalid_host_operation_id");
    const bytes = canonicalJSONStringify(proposal);
    if (typeof bytes !== "string" || Buffer.byteLength(bytes) > 65536) throw new TypeError("invalid_proposal_bytes");
    const operation_sha256 = hex(operationId);
    return { operation_sha256, proposal_sha256: hex(bytes), frozen: freezeDeep(JSON.parse(bytes)),
      claimFile: path.join(root, `${operation_sha256}.claim.json`),
      outcomeFile: path.join(root, `${operation_sha256}.outcome.json`) };
  };
  const view = (data, status, reason) => ({ protocol: "aml-file-dispatch-ledger/1",
    operation_sha256: data.operation_sha256, proposal_sha256: data.proposal_sha256,
    status, reason });

  function inspectData(data) {
    const claim = readRecord(data.claimFile);
    if (!claim) return fs.existsSync(data.claimFile) ? view(data, "unknown", "incomplete_claim") :
      view(data, "unclaimed", "no_claim");
    if (claim.protocol !== "aml-file-dispatch-claim/1" || claim.operation_sha256 !== data.operation_sha256 ||
        !DIGEST.test(claim.proposal_sha256)) return view(data, "unknown", "invalid_claim");
    if (claim.proposal_sha256 !== data.proposal_sha256) return view(data, "mismatch", "operation_payload_mismatch");
    if (!fs.existsSync(data.outcomeFile)) return view(data, "unknown", "claimed_may_have_executed");
    const outcome = readRecord(data.outcomeFile);
    if (!outcome || outcome.protocol !== "aml-file-dispatch-outcome/1" ||
        outcome.operation_sha256 !== data.operation_sha256 || outcome.proposal_sha256 !== data.proposal_sha256 ||
        !["returned", "unknown"].includes(outcome.status)) return view(data, "unknown", "invalid_outcome");
    return view(data, outcome.status === "returned" ? "already_returned" : "unknown", outcome.reason);
  }

  function inspect({ operationId, proposal }) {
    return inspectData(input(operationId, proposal));
  }

  function claimData(data) {
    if (!createExclusive(data.claimFile, { protocol: "aml-file-dispatch-claim/1",
      operation_sha256: data.operation_sha256, proposal_sha256: data.proposal_sha256 }, root)) {
      return inspectData(data);
    }
    return view(data, "claimed", "claimed_before_callback");
  }

  function claim({ operationId, proposal }) {
    return claimData(input(operationId, proposal));
  }

  async function run({ operationId, proposal, executeTool }) {
    if (typeof executeTool !== "function") throw new TypeError("host_callback_required");
    const data = input(operationId, proposal);
    const first = claimData(data);
    if (first.status !== "claimed") return first; // No retry, even after a crash or callback error.
    let result;
    let outcome;
    try {
      result = await executeTool(data.frozen);
      outcome = { status: "returned", reason: "host_callback_returned" };
    } catch {
      outcome = { status: "unknown", reason: "host_callback_threw" };
    }
    try {
      if (!createExclusive(data.outcomeFile, { protocol: "aml-file-dispatch-outcome/1",
        operation_sha256: data.operation_sha256, proposal_sha256: data.proposal_sha256, ...outcome }, root)) {
        return view(data, "unknown", "outcome_record_conflict");
      }
    } catch { return view(data, "unknown", "outcome_record_unavailable"); }
    return outcome.status === "returned" ? { ...view(data, "returned", outcome.reason), result } :
      view(data, "unknown", outcome.reason);
  }

  return { claim, inspect, run };
}
