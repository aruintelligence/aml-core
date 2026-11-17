// Signed, versioned trust configuration (TUF-style root of trust).
//
// A trust config is one document that replaces per-flag pins. Its `signed`
// body names the trusted signing keys (with roles), revoked keys, and the
// policy / revocation-registry / profile digests a relying party accepts. It
// carries a monotonically increasing `version` and an `expires_at`, and it is
// valid only when a threshold of ROOT keys has signed it.
//
// Established techniques only (The Update Framework root metadata, RFC 6962-
// style append-only state, Chrome/Android style time floors):
//   - threshold signatures by root keys (k-of-n, each key counted once);
//   - root rotation needs a threshold of the CURRENT root and of the NEW root;
//   - rollback protection: the highest accepted version is persisted locally
//     in an append-only directory; a lower version is refused and the same
//     version with different bytes is refused as a fork;
//   - expiry against the verifier's own clock only. A caller-supplied time
//     (AML_VERIFY_AT, --now) never authorizes. The local clock is refused when
//     it is earlier than the persisted time floor (the latest issued_at /
//     accepted_at already seen), so winding the clock back fails closed;
//   - revocations are sticky: a key revoked in any accepted version stays
//     revoked in every later version (rotate to a new key instead).
//
// evaluateTrustConfig never returns `trusted: true` unless every check is
// explicitly true. It never weakens an explicit pin: callers AND the config
// result with any pin they also hold.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

export const TRUST_CONFIG_TYPE = "aml-trust-config/1";
export const TRUST_ANCHOR_TYPE = "aml-trust-anchor/1";
export const TRUST_STATE_RECORD_TYPE = "aml-trust-state-record/1";
// A root-owned system location. When it holds an anchor, every verifier on
// the host requires a trust config; an environment variable can add another
// enrolled state directory but cannot remove this one.
export const AML_SYSTEM_TRUST_STATE_DIR = "/etc/aml/trust";
export const TRUST_ROLES = Object.freeze(["receipt", "policy-pack", "build-attestation", "brand-authorization", "capability-issuer"]);

const HEX64 = /^[a-f0-9]{64}$/;
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$/;
const MAX_KEYS = 64;
const MAX_STATE_RECORDS = 100000;
const RECORD_FILE = /^v(\d{12})\.json$/;
// Decisions produced by this module. A JSON look-alike never counts as trusted.
const ISSUED = new WeakSet();
const issue = decision => {
  Object.freeze(decision.reasons); Object.freeze(decision.checks);
  if (decision.effective) { Object.freeze(decision.effective.trusted_keys); Object.freeze(decision.effective.revoked_keys); }
  ISSUED.add(Object.freeze(decision)); return decision;
};
// A trusted decision stays usable only until the config's own expiry.
const stillUnexpired = decision => typeof decision.expires_at === "string" && Date.now() < Date.parse(decision.expires_at);
export function isIssuedTrustDecision(decision) { return Boolean(decision) && typeof decision === "object" && ISSUED.has(decision); }

// Strict encodings shared with the Python and Go verifiers so every
// implementation accepts exactly the same bytes (conformance vectors in
// conformance/trust-config/). PEM: canonical SPKI armor, 64-column base64.
// Signature: canonical 64-byte Ed25519 base64. Keys: Ed25519 only.
const PEM = /^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/]{64}\n)*[A-Za-z0-9+/]{1,63}={0,2}\n-----END PUBLIC KEY-----\n?$/;
const SIG_B64 = /^[A-Za-z0-9+/]{85}[AQgw]==$/;
export function keyFingerprint(publicKeyPem) {
  if (typeof publicKeyPem !== "string" || !PEM.test(publicKeyPem)) throw new Error("AML_TRUST_KEY_PEM_INVALID");
  const key = crypto.createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("AML_TRUST_KEY_NOT_ED25519");
  const der = key.export({ type: "spki", format: "der" });
  // The armored bytes must already be the canonical 44-byte SPKI encoding.
  const armored = Buffer.from(publicKeyPem.replace(/-----[A-Z ]+-----|\n/g, ""), "base64");
  if (der.length !== 44 || !der.equals(armored)) throw new Error("AML_TRUST_KEY_NOT_CANONICAL");
  return crypto.createHash("sha256").update(der).digest("hex");
}
export function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJSONStringify(value)).digest("hex");
}
// Calendar-exact: Date.parse accepts 2026-02-30 and 24:00; these do not.
const isIso = v => {
  if (typeof v !== "string" || !ISO.test(v)) return false;
  const [y, mo, d, h, mi, se] = [v.slice(0, 4), v.slice(5, 7), v.slice(8, 10), v.slice(11, 13), v.slice(14, 16), v.slice(17, 19)].map(Number);
  const date = new Date(Date.UTC(y, mo - 1, d, h, mi, se));
  return y >= 1970 && date.getUTCFullYear() === y && date.getUTCMonth() === mo - 1 && date.getUTCDate() === d
    && date.getUTCHours() === h && date.getUTCMinutes() === mi && date.getUTCSeconds() === se;
};
const uniqueHexList = (v, { min = 0 } = {}) => Array.isArray(v) && v.length >= min && v.length <= MAX_KEYS
  && v.every(x => typeof x === "string" && HEX64.test(x)) && new Set(v).size === v.length;
const optionalDigest = v => v === null || (typeof v === "string" && HEX64.test(v));

export function validRoot(root) {
  return Boolean(root) && typeof root === "object" && !Array.isArray(root)
    && Object.keys(root).sort().join() === "keyids,threshold"
    && uniqueHexList(root.keyids, { min: 1 }) && Number.isSafeInteger(root.threshold)
    && root.threshold >= 1 && root.threshold <= root.keyids.length;
}

const BODY_KEYS = ["expires_at", "issued_at", "policy_sha256", "profile_sha256", "registry_sha256", "require_single_use",
  "revoked_keys", "root", "trusted_keys", "type", "version"];

// Structural validation of the signed body. Unknown fields are refused so a
// verifier never silently ignores a constraint it does not understand.
export function validateTrustConfigBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "body_not_object";
  if (Object.keys(body).sort().join() !== BODY_KEYS.join()) return "body_fields";
  if (body.type !== TRUST_CONFIG_TYPE) return "type";
  if (!Number.isSafeInteger(body.version) || body.version < 1 || body.version > 999999999999) return "version";
  if (!isIso(body.issued_at) || !isIso(body.expires_at) || Date.parse(body.expires_at) <= Date.parse(body.issued_at)) return "time_window";
  if (!validRoot(body.root)) return "root";
  if (!Array.isArray(body.trusted_keys) || body.trusted_keys.length > MAX_KEYS) return "trusted_keys";
  const seen = new Set();
  for (const entry of body.trusted_keys) {
    if (!entry || typeof entry !== "object" || Object.keys(entry).sort().join() !== "keyid,roles") return "trusted_keys";
    if (typeof entry.keyid !== "string" || !HEX64.test(entry.keyid) || seen.has(entry.keyid)) return "trusted_keys";
    seen.add(entry.keyid);
    if (!Array.isArray(entry.roles) || entry.roles.length === 0 || new Set(entry.roles).size !== entry.roles.length
      || !entry.roles.every(r => TRUST_ROLES.includes(r))) return "trusted_key_roles";
  }
  if (!uniqueHexList(body.revoked_keys)) return "revoked_keys";
  if (!optionalDigest(body.policy_sha256) || !optionalDigest(body.registry_sha256) || !optionalDigest(body.profile_sha256)) return "digests";
  if (typeof body.require_single_use !== "boolean") return "require_single_use";
  return null;
}

export function signTrustConfig(body, rootPrivateKeyPems) {
  const error = validateTrustConfigBody(body);
  if (error) throw new Error(`AML_TRUST_CONFIG_INVALID_${error.toUpperCase()}`);
  const message = Buffer.from(canonicalJSONStringify(body));
  const signatures = rootPrivateKeyPems.map(pem => {
    const privateKey = crypto.createPrivateKey(pem);
    const publicPem = crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
    return { keyid: keyFingerprint(publicPem), public_key_pem: publicPem,
      signature_base64: crypto.sign(null, message, privateKey).toString("base64") };
  });
  return { signed: body, signatures };
}

// Count distinct root keys in `root` with a valid signature over the body.
function countThreshold(envelope, root) {
  const message = Buffer.from(canonicalJSONStringify(envelope.signed));
  const good = new Set();
  for (const sig of envelope.signatures) {
    try {
      if (!sig || typeof sig !== "object" || typeof sig.public_key_pem !== "string" || typeof sig.signature_base64 !== "string"
        || !SIG_B64.test(sig.signature_base64)) continue;
      const id = keyFingerprint(sig.public_key_pem);
      if (id !== sig.keyid || !root.keyids.includes(id) || good.has(id)) continue;
      if (crypto.verify(null, message, crypto.createPublicKey(sig.public_key_pem), Buffer.from(sig.signature_base64, "base64"))) good.add(id);
    } catch { /* a malformed signature never counts */ }
  }
  return good.size;
}

function fsyncDir(dir) {
  let fd = null;
  try { fd = fs.openSync(dir, "r"); fs.fsyncSync(fd); } catch { /* some platforms cannot fsync a directory */ } finally { if (fd !== null) fs.closeSync(fd); }
}

// Create a file exclusively and durably. Returns false if it already exists.
export function createExclusiveDurable(file, contents) {
  let fd;
  try { fd = fs.openSync(file, "wx", 0o600); } catch (error) { if (error.code === "EEXIST") return false; throw error; }
  try { fs.writeSync(fd, contents); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fsyncDir(path.dirname(file));
  return true;
}

function readJSONFile(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

// Enroll a host: write the out-of-band root anchor once. It cannot be
// overwritten by this API (exclusive create); re-enrolling needs a new dir.
export function initTrustState(stateDir, { threshold, rootKeyids }) {
  const root = { keyids: [...rootKeyids], threshold };
  if (!validRoot(root)) throw new Error("AML_TRUST_ANCHOR_INVALID_ROOT");
  fs.mkdirSync(path.join(stateDir, "versions"), { recursive: true, mode: 0o700 });
  const anchor = { type: TRUST_ANCHOR_TYPE, root };
  if (!createExclusiveDurable(path.join(stateDir, "anchor.json"), `${JSON.stringify(anchor, null, 2)}\n`)) {
    throw new Error("AML_TRUST_ANCHOR_EXISTS");
  }
  return anchor;
}

export function trustStateEnrolled(stateDir) {
  return typeof stateDir === "string" && stateDir.length > 0 && fs.existsSync(path.join(stateDir, "anchor.json"));
}

// Read anchor + every accepted version record. Any unreadable or malformed
// state is an error (fail closed), never "no state".
export function readTrustState(stateDir) {
  const anchor = readJSONFile(path.join(stateDir, "anchor.json"));
  if (anchor?.type !== TRUST_ANCHOR_TYPE || !validRoot(anchor.root)) throw new Error("AML_TRUST_ANCHOR_INVALID");
  const versionsDir = path.join(stateDir, "versions");
  const names = fs.existsSync(versionsDir) ? fs.readdirSync(versionsDir) : [];
  if (names.length > MAX_STATE_RECORDS) throw new Error("AML_TRUST_STATE_TOO_LARGE");
  const records = [];
  for (const name of names) {
    const match = RECORD_FILE.exec(name);
    if (!match) { if (name.startsWith(".")) continue; throw new Error("AML_TRUST_STATE_UNEXPECTED_FILE"); }
    const record = readJSONFile(path.join(versionsDir, name));
    if (record?.type !== TRUST_STATE_RECORD_TYPE || record.version !== Number(match[1]) || !HEX64.test(record.config_sha256 || "")
      || !validRoot(record.root) || !uniqueHexList(record.revoked_keys) || !isIso(record.issued_at) || !isIso(record.accepted_at)) {
      throw new Error("AML_TRUST_STATE_RECORD_INVALID");
    }
    records.push(record);
  }
  records.sort((a, b) => a.version - b.version);
  const latest = records.at(-1) || null;
  const revoked = new Set(records.flatMap(r => r.revoked_keys));
  const floorMs = records.reduce((m, r) => Math.max(m, Date.parse(r.issued_at), Date.parse(r.accepted_at)), -Infinity);
  return { anchor, records, latest, root: latest ? latest.root : anchor.root, revoked, floorMs };
}

const recordName = version => `v${String(version).padStart(12, "0")}.json`;
const sameRoot = (a, b) => a.threshold === b.threshold && [...a.keyids].sort().join() === [...b.keyids].sort().join();

const CHECKS = ["anchor_present", "state_readable", "envelope_well_formed", "root_threshold_met", "new_root_threshold_met",
  "not_rolled_back", "no_version_fork", "caller_time_absent", "trusted_time", "issued_not_in_future", "not_expired", "state_persisted"];

// Evaluate a signed trust config against one enrolled state directory and,
// when every check passes, persist it (append-only) as the newest version.
// `callerTime` is whatever time the caller tried to supply (env/flag); its
// mere presence denies. There is deliberately no option to supply "now".
// `onBeforePersist` is a test seam: it runs after every pre-check passed and
// before the record is written, so a test can deterministically land a newer
// version in between. It cannot make a decision trusted: the post-write
// re-read of the state on disk decides.
export function evaluateTrustConfig(envelope, { stateDir, callerTime = null, onBeforePersist = null } = {}) {
  const checks = Object.fromEntries(CHECKS.map(name => [name, false]));
  const result = (extra = {}) => {
    const reasons = CHECKS.filter(name => checks[name] !== true);
    return issue({ schema: "aml-trust-config-decision/1", trusted: reasons.length === 0, reasons, checks, ...extra });
  };
  checks.anchor_present = trustStateEnrolled(stateDir);
  if (!checks.anchor_present) return result();
  let state;
  try { state = readTrustState(stateDir); checks.state_readable = true; } catch { return result(); }
  const bodyError = envelope && typeof envelope === "object" && !Array.isArray(envelope)
    && Object.keys(envelope).sort().join() === "signatures,signed" && Array.isArray(envelope.signatures)
    && envelope.signatures.length <= MAX_KEYS ? validateTrustConfigBody(envelope.signed) : "envelope";
  checks.envelope_well_formed = bodyError === null;
  if (!checks.envelope_well_formed) return result({ body_error: bodyError });
  const body = envelope.signed;
  const configSha256 = sha256Canonical(body);
  checks.root_threshold_met = countThreshold(envelope, state.root) >= state.root.threshold;
  checks.new_root_threshold_met = sameRoot(body.root, state.root) || countThreshold(envelope, body.root) >= body.root.threshold;
  const latestVersion = state.latest ? state.latest.version : 0;
  checks.not_rolled_back = body.version >= latestVersion;
  const existing = state.records.find(r => r.version === body.version);
  checks.no_version_fork = !existing || existing.config_sha256 === configSha256;
  const nowMs = Date.now();
  checks.caller_time_absent = callerTime === null || callerTime === undefined || callerTime === "";
  checks.trusted_time = Number.isFinite(nowMs) && (state.floorMs === -Infinity || nowMs >= state.floorMs);
  checks.issued_not_in_future = nowMs >= Date.parse(body.issued_at);
  checks.not_expired = nowMs < Date.parse(body.expires_at);
  if (CHECKS.filter(n => n !== "state_persisted").some(n => checks[n] !== true)) return result({ config_sha256: configSha256, version: body.version });
  // Persist before reporting trusted. Exclusive create: concurrent writers
  // can only add versions, never replace one.
  try {
    if (typeof onBeforePersist === "function") onBeforePersist();
    if (!existing) {
      const revoked = [...new Set([...state.revoked, ...body.revoked_keys])].sort();
      const record = { type: TRUST_STATE_RECORD_TYPE, version: body.version, config_sha256: configSha256, root: body.root,
        revoked_keys: revoked, issued_at: body.issued_at, accepted_at: new Date(nowMs).toISOString() };
      const created = createExclusiveDurable(path.join(stateDir, "versions", recordName(body.version)), `${JSON.stringify(record)}\n`);
      if (!created) {
        const raced = readJSONFile(path.join(stateDir, "versions", recordName(body.version)));
        if (raced.config_sha256 !== configSha256) { checks.no_version_fork = false; return result({ config_sha256: configSha256 }); }
      }
    }
    // A newer version accepted concurrently makes this one a rollback.
    const after = readTrustState(stateDir);
    checks.not_rolled_back = after.latest.version === body.version;
    state = after;
    checks.state_persisted = checks.not_rolled_back;
  } catch {
    checks.state_persisted = false;
  }
  const revoked = state.revoked;
  const trustedKeys = body.trusted_keys.filter(k => !revoked.has(k.keyid) && !body.revoked_keys.includes(k.keyid));
  return result({
    config_sha256: configSha256, version: body.version, expires_at: body.expires_at,
    effective: Object.freeze({
      trusted_keys: trustedKeys.map(k => ({ keyid: k.keyid, roles: [...k.roles] })),
      revoked_keys: [...revoked].sort(),
      policy_sha256: body.policy_sha256, registry_sha256: body.registry_sha256, profile_sha256: body.profile_sha256,
      require_single_use: body.require_single_use
    })
  });
}

// True only for a trusted decision whose effective key set grants `role` to
// `keyid` and has not revoked it.
export function trustConfigRequiresSingleUse(decision) {
  // Fail closed: an untrusted or look-alike decision also "requires" it.
  return !(isIssuedTrustDecision(decision) && decision.trusted === true && decision.effective?.require_single_use === false);
}

export function trustConfigTrustsKey(decision, keyid, role) {
  return isIssuedTrustDecision(decision) && decision.trusted === true && decision.reasons?.length === 0 && stillUnexpired(decision) && typeof keyid === "string" && HEX64.test(keyid)
    && TRUST_ROLES.includes(role) && !decision.effective.revoked_keys.includes(keyid)
    && decision.effective.trusted_keys.some(k => k.keyid === keyid && k.roles.includes(role));
}

// Digest pins from a trusted config. A null digest in the config pins nothing
// and therefore never satisfies a digest condition.
export function trustConfigPinMatches(decision, field, actual) {
  if (!isIssuedTrustDecision(decision) || decision.trusted !== true || !stillUnexpired(decision) || !["policy_sha256", "registry_sha256", "profile_sha256"].includes(field)) return false;
  const pin = decision.effective[field];
  return typeof pin === "string" && HEX64.test(pin) && actual === pin;
}

// State directories that are enrolled on this host. The system directory is
// always consulted; `extraDirs` (env/flag) can only add enrolled directories.
export function enrolledTrustStateDirs(extraDirs = [], { systemDir = AML_SYSTEM_TRUST_STATE_DIR } = {}) {
  const dirs = [systemDir, ...extraDirs].filter(d => typeof d === "string" && d.length > 0).map(d => path.resolve(d));
  return [...new Set(dirs)].filter(trustStateEnrolled);
}

// Evaluate the config against every enrolled directory; all must agree.
export function evaluateTrustConfigAll(envelope, { stateDirs, callerTime = null } = {}) {
  if (!Array.isArray(stateDirs) || stateDirs.length === 0) {
    return issue({ schema: "aml-trust-config-decision/1", trusted: false, reasons: ["anchor_present"], checks: { anchor_present: false } });
  }
  const decisions = stateDirs.map(stateDir => evaluateTrustConfig(envelope, { stateDir, callerTime }));
  const denied = decisions.find(d => d.trusted !== true);
  if (denied) return denied;
  const first = decisions[0];
  // Intersect effective keys and sticky revocations across directories.
  const revoked = [...new Set(decisions.flatMap(d => d.effective.revoked_keys))].sort();
  const trusted = first.effective.trusted_keys.filter(k => !revoked.includes(k.keyid));
  return issue({ ...first, effective: Object.freeze({ ...first.effective, trusted_keys: trusted, revoked_keys: revoked }) });
}
