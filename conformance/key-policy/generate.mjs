// Generate conformance/key-policy/vectors.json: the Ed25519-only rule for
// capability tokens and threshold authorizations, as signed artifacts that
// JS, Python and Go must decide identically. SYNTHETIC canary keys only, and
// no private key is written. Ed25519 keys are derived from public labels; the
// ECDSA / RSA / RSA-PSS / Ed448 artifacts are signed with throwaway keys
// generated at run time (their signatures are randomized), so `--check`
// re-derives every Ed25519 vector byte-for-byte and re-verifies every
// committed decision instead of regenerating the non-Ed25519 bytes.
// Run: node conformance/key-policy/generate.mjs [--check]
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { runVectors } from "./run-js.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, "vectors.json");
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

function canaryEd25519(label) {
  const seed = crypto.createHash("sha256").update(`aml-key-policy-canary/1\0${label}`).digest();
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
}
const throwaway = {
  "ecdsa-p256": () => crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey,
  "ecdsa-p384": () => crypto.generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey,
  "rsa-2048": () => crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey,
  "rsa-pss-2048": () => crypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048 }).privateKey,
  ed448: () => crypto.generateKeyPairSync("ed448").privateKey
};
const spkiPem = privateKey => crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
const fp = privateKey => crypto.createHash("sha256").update(crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" })).digest("hex");
// Raw signing (bypasses the Ed25519-only signers on purpose, to build the
// artifacts an attacker or a legacy producer could still present).
const rawSign = (message, privateKey) => crypto.sign(privateKey.asymmetricKeyType === "rsa-pss" || privateKey.asymmetricKeyType === "ec"
  || privateKey.asymmetricKeyType === "rsa" ? "sha256" : null, message, privateKey).toString("base64");

function token(privateKey, over = {}) {
  const body = { type: "aml-capability-token/1", issuer: "synthetic-canary-issuer", subject: "synthetic-executor",
    audience: "synthetic-audience", capabilities: ["canary.read"], issued_at: "2026-01-01T00:00:00.000Z",
    expires_at: "2099-01-01T00:00:00.000Z", nonce: "canary-nonce-0001", ...over };
  return { ...body, public_key_pem: spkiPem(privateKey), public_key_fingerprint: fp(privateKey),
    signature_base64: rawSign(Buffer.from(canonicalJSONStringify(body)), privateKey) };
}
function threshold(privateKeys, k, payload = { action: "canary-publish", policy_sha256: "c".repeat(64) }) {
  const body = { type: "aml-threshold-authorization/1", version: "1.1", threshold: k, payload };
  const message = Buffer.from(canonicalJSONStringify({ context: body.type, version: body.version, threshold: k, payload }));
  return { ...body, signatures: privateKeys.map(key => ({ key_fingerprint: fp(key), public_key_pem: spkiPem(key),
    signature_base64: rawSign(message, key) })) };
}
// ECDSA malleability: (r, s) -> (r, n - s) is a second valid signature.
function malleateP256(signatureBase64) {
  const der = Buffer.from(signatureBase64, "base64");
  let i = 2; const rLen = der[i + 1]; const r = der.subarray(i + 2, i + 2 + rLen); i += 2 + rLen;
  const sLen = der[i + 1]; const s = BigInt(`0x${der.subarray(i + 2, i + 2 + sLen).toString("hex")}`);
  let hex = (P256_N - s).toString(16); if (hex.length % 2) hex = `0${hex}`;
  let s2 = Buffer.from(hex, "hex"); if (s2[0] & 0x80) s2 = Buffer.concat([Buffer.from([0]), s2]);
  const seq = Buffer.concat([Buffer.from([2, r.length]), r, Buffer.from([2, s2.length]), s2]);
  return Buffer.concat([Buffer.from([0x30, seq.length]), seq]).toString("base64");
}

const E = [0, 1, 2].map(i => canaryEd25519(`signer-${i}`));
const deny = (reason, extra = {}) => ({ valid: false, reason, ...extra });

function ed25519Cases() {
  const good = token(E[0]);
  const tampered = { ...good, capabilities: ["canary.admin"] };
  const wrongFp = { ...good, public_key_fingerprint: fp(E[1]) };
  const t = threshold(E, 2);
  const lowered = { ...structuredClone(t), threshold: 1 };
  const legacy = structuredClone(t); delete legacy.version;
  const garbageKey = structuredClone(t); garbageKey.signatures.push({ key_fingerprint: "0".repeat(64),
    public_key_pem: "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----\n", signature_base64: "AAAA" });
  const dup = threshold([E[0]], 2); dup.signatures.push(structuredClone(dup.signatures[0]));
  return [
    { name: "token_ed25519_valid", kind: "capability-token", artifact: good, expect: { valid: true, reason: null } },
    { name: "token_ed25519_tampered_body", kind: "capability-token", artifact: tampered, expect: deny("signature_invalid") },
    { name: "token_ed25519_fingerprint_mismatch", kind: "capability-token", artifact: wrongFp, expect: deny("fingerprint_mismatch") },
    { name: "token_wrong_type", kind: "capability-token", artifact: { ...good, type: "aml-capability-token/0" }, expect: deny("invalid_type") },
    { name: "token_unparseable_key", kind: "capability-token", artifact: { ...good, public_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n" }, expect: deny("signature_invalid") },
    { name: "threshold_ed25519_2_of_3_valid", kind: "threshold-authorization", artifact: t, expect: { valid: true, reason: null, valid_signatures: 3, rejected_key_types: [] } },
    { name: "threshold_ed25519_lowered_threshold", kind: "threshold-authorization", artifact: lowered, expect: deny("threshold_not_met", { valid_signatures: 0, rejected_key_types: [] }) },
    { name: "threshold_legacy_unversioned", kind: "threshold-authorization", artifact: legacy, expect: deny("legacy_threshold_unbound", { valid_signatures: 0, rejected_key_types: [] }) },
    { name: "threshold_invalid_threshold", kind: "threshold-authorization", artifact: { ...structuredClone(t), threshold: 0 }, expect: deny("invalid_threshold", { valid_signatures: 0, rejected_key_types: [] }) },
    { name: "threshold_signatures_not_array", kind: "threshold-authorization", artifact: { ...structuredClone(t), signatures: { a: 1 } }, expect: deny("invalid_signatures", { valid_signatures: 0, rejected_key_types: [] }) },
    { name: "threshold_unparseable_key_entry_is_a_failed_signer", kind: "threshold-authorization", artifact: garbageKey, expect: { valid: true, reason: null, valid_signatures: 3, rejected_key_types: [] } },
    { name: "threshold_duplicate_signer_counted_once", kind: "threshold-authorization", artifact: dup, expect: deny("threshold_not_met", { valid_signatures: 1, rejected_key_types: [] }) }
  ];
}

function foreignCases() {
  const out = [];
  const nodeType = { "ecdsa-p256": "ec", "ecdsa-p384": "ec", "rsa-2048": "rsa", "rsa-pss-2048": "rsa-pss", ed448: "ed448" };
  for (const [label, make] of Object.entries(throwaway)) {
    const key = make();
    const tok = token(key);
    out.push({ name: `token_${label}_signature_valid_but_refused`, kind: "capability-token", artifact: tok, expect: deny("key_type_not_ed25519") });
    out.push({ name: `threshold_${label}_only_refused`, kind: "threshold-authorization", artifact: threshold([key], 1),
      expect: deny("key_type_not_ed25519", { valid_signatures: 0, rejected_key_types: [nodeType[label]] }) });
    if (label === "ecdsa-p256") {
      out.push({ name: "token_ecdsa_p256_malleated_high_s_refused", kind: "capability-token",
        artifact: { ...tok, signature_base64: malleateP256(tok.signature_base64) }, expect: deny("key_type_not_ed25519") });
      // Two valid Ed25519 signers meet threshold 2; one extra ECDSA entry still refuses the whole artifact.
      out.push({ name: "threshold_mixed_ed25519_quorum_plus_ecdsa_refused", kind: "threshold-authorization", artifact: threshold([E[0], E[1], key], 2),
        expect: deny("key_type_not_ed25519", { valid_signatures: 0, rejected_key_types: ["ec"] }) });
    }
  }
  return out;
}

const check = process.argv.includes("--check");
const header = {
  type: "aml-key-policy-vectors/1",
  rule: "capability tokens and threshold authorizations accept Ed25519 keys only, with or without a trust config",
  synthetic_canary_keys_only: true,
  note: "Ed25519 vectors are byte-reproducible; non-Ed25519 artifacts were signed with throwaway keys (randomized signatures), and --check re-verifies their decisions"
};
if (check) {
  const committed = JSON.parse(fs.readFileSync(OUT, "utf8"));
  const fresh = ed25519Cases();
  const problems = [];
  for (const c of fresh) {
    const old = committed.cases.find(x => x.name === c.name);
    if (!old || canonicalJSONStringify(old) !== canonicalJSONStringify(c)) problems.push(`stale Ed25519 vector ${c.name}`);
  }
  if (/PRIVATE KEY/.test(fs.readFileSync(OUT, "utf8"))) problems.push("private key material in vectors");
  const js = runVectors(committed);
  committed.cases.forEach((c, i) => { if (canonicalJSONStringify(js.results[i].decision) !== canonicalJSONStringify(c.expect)) problems.push(`decision ${c.name}`); });
  if (problems.length) { console.error(problems.join("\n")); process.exit(1); }
  console.log(JSON.stringify({ ok: true, cases: committed.cases.length }));
} else {
  const vectors = { ...header, cases: [...ed25519Cases(), ...foreignCases()] };
  fs.writeFileSync(OUT, `${JSON.stringify(vectors, null, 2)}\n`);
  console.log(JSON.stringify({ wrote: OUT, cases: vectors.cases.length }));
}
