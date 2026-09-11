import crypto from "node:crypto";
import { canonicalJSONStringify } from "./canonicalJson.js";
import {
  createGovernanceStreamSession,
  AML_GOVERNANCE_STREAM_OPEN,
  AML_GOVERNANCE_STREAM_FINALIZE
} from "./governanceStream.js";

export const AML_GOVERNANCE_TRANSCRIPT = "aml-governance-stream-transcript/1";
export const AML_GOVERNANCE_TRANSCRIPT_VERIFICATION = "aml-governance-stream-transcript-verification/1";

function sha256(value) {
  return crypto.createHash("sha256").update(canonicalJSONStringify(value)).digest("hex");
}

function addEntry(entries, direction, message) {
  const previousHash = entries.at(-1)?.entry_sha256 || null;
  const sequence = entries.length + 1;
  const material = {
    sequence,
    direction,
    previous_sha256: previousHash,
    message
  };
  const entry = {
    ...structuredClone(material),
    entry_sha256: sha256(material)
  };
  entries.push(entry);
  return entry;
}

function acceptedOpen(session) {
  return {
    protocol: AML_GOVERNANCE_STREAM_OPEN,
    accepted: true,
    transmission: session.transmission,
    profile: session.profile,
    mode: session.mode,
    failure_mode: session.failure_mode
  };
}

export function createGovernanceStreamTranscript(messages) {
  if (!Array.isArray(messages) || messages.length < 2) {
    throw new Error("messages must be an array containing open and finalize messages");
  }
  if (messages[0]?.protocol !== AML_GOVERNANCE_STREAM_OPEN) {
    throw new Error("first transcript message must be aml-governance-stream-open/1");
  }
  if (messages.at(-1)?.protocol !== AML_GOVERNANCE_STREAM_FINALIZE) {
    throw new Error("last transcript message must be aml-governance-stream-finalize/1");
  }

  const entries = [];
  const session = createGovernanceStreamSession(messages[0]);
  addEntry(entries, "input", messages[0]);
  addEntry(entries, "output", acceptedOpen(session));

  for (const message of messages.slice(1)) {
    addEntry(entries, "input", message);
    addEntry(entries, "output", session.accept(message));
  }

  return {
    protocol: AML_GOVERNANCE_TRANSCRIPT,
    transmission: session.transmission,
    hash_algorithm: "sha256",
    canonicalization: "aml-canonical-json",
    entry_count: entries.length,
    root_sha256: entries.at(-1)?.entry_sha256 || null,
    entries
  };
}

function verifyHashChain(transcript) {
  if (!Array.isArray(transcript.entries)) return { valid: false, error: "entries must be an array" };
  let previous = null;
  for (let index = 0; index < transcript.entries.length; index += 1) {
    const entry = transcript.entries[index];
    const sequence = index + 1;
    if (entry.sequence !== sequence) return { valid: false, error: `entry ${sequence} has invalid sequence` };
    if (entry.previous_sha256 !== previous) return { valid: false, error: `entry ${sequence} has invalid previous_sha256` };
    const expected = sha256({
      sequence: entry.sequence,
      direction: entry.direction,
      previous_sha256: entry.previous_sha256,
      message: entry.message
    });
    if (entry.entry_sha256 !== expected) return { valid: false, error: `entry ${sequence} hash mismatch` };
    previous = entry.entry_sha256;
  }
  if ((transcript.root_sha256 || null) !== previous) return { valid: false, error: "root_sha256 mismatch" };
  return { valid: true, error: null };
}

export function verifyGovernanceStreamTranscript(transcript) {
  const errors = [];
  if (!transcript || typeof transcript !== "object" || Array.isArray(transcript)) {
    return {
      protocol: AML_GOVERNANCE_TRANSCRIPT_VERIFICATION,
      valid: false,
      hash_chain_valid: false,
      replay_valid: false,
      errors: ["transcript must be an object"]
    };
  }
  if (transcript.protocol !== AML_GOVERNANCE_TRANSCRIPT) errors.push("unsupported transcript protocol");

  const chain = verifyHashChain(transcript);
  if (!chain.valid) errors.push(chain.error);

  let replayValid = false;
  try {
    const inputEntries = transcript.entries.filter(entry => entry.direction === "input");
    const outputEntries = transcript.entries.filter(entry => entry.direction === "output");
    const inputMessages = inputEntries.map(entry => entry.message);
    const replayed = createGovernanceStreamTranscript(inputMessages);
    const replayOutputs = replayed.entries.filter(entry => entry.direction === "output").map(entry => entry.message);
    const recordedOutputs = outputEntries.map(entry => entry.message);
    replayValid = canonicalJSONStringify(replayOutputs) === canonicalJSONStringify(recordedOutputs);
    if (!replayValid) errors.push("replayed outputs differ from recorded outputs");
  } catch (error) {
    errors.push(`replay failed: ${error.message || String(error)}`);
  }

  return {
    protocol: AML_GOVERNANCE_TRANSCRIPT_VERIFICATION,
    valid: errors.length === 0 && chain.valid && replayValid,
    hash_chain_valid: chain.valid,
    replay_valid: replayValid,
    entry_count: transcript.entries?.length ?? null,
    root_sha256: transcript.root_sha256 ?? null,
    errors
  };
}
