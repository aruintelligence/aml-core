// Stable wire bytes for future implementations. All seeds are public test data.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { executeAccountableIntent } from "../compiler/accountablePipeline.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { createEvidenceRenewal, attestEvidenceRenewal } from "../runtime/evidenceRenewal.js";
import { createEvidenceArchive, verifyEvidenceArchive } from "../runtime/evidenceArchive.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../independent/vectors/archive-v1");
const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const privateKey = byte => crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, Buffer.alloc(32, byte)]), format: "der", type: "pkcs8" })
  .export({ type: "pkcs8", format: "pem" });
const keys = [0x11, 0x22, 0x33].map(privateKey);
const intent = { transmission: "public-archive-vector", nodes: [{ type: "message", identifier: "Guidance", properties: {
  purpose: "Explain the next step", user_effect: "Reduce uncertainty", attention_cost: 1, restoration_value: 3,
  collects_personal_data: false, consent_required: false, contrast_safe: true, cognitive_load: 1
} }] };
const receipt = executeAccountableIntent(intent, { timestamp: "2026-10-10T00:00:00.000Z", profile: "human_first" });
const capsule = createEvidenceCapsule(receipt);
const first = createEvidenceRenewal(capsule, { sequence: 1, created_at: "2026-10-10T01:00:00.000Z" });
const second = createEvidenceRenewal(capsule, { sequence: 2, previous_root_sha3_512: first.root_sha3_512, created_at: "2026-10-10T02:00:00.000Z" });
const attest = (record, key, signer) => attestEvidenceRenewal(record, key, { signer, signed_at: record.created_at });
const firstWitnesses = [attest(first, keys[0], "synthetic-1"), attest(first, keys[1], "synthetic-2")];
const secondWitnesses = [attest(second, keys[1], "synthetic-2"), attest(second, keys[2], "synthetic-3")];
const fingerprints = [...firstWitnesses.map(w => w.public_key_fingerprint_sha256), secondWitnesses[1].public_key_fingerprint_sha256];
const policy = { threshold: 2, trusted_fingerprints: fingerprints,
  trusted_fingerprints_by_sequence: { 1: fingerprints.slice(0, 2), 2: fingerprints.slice(1) },
  accepted_head: { sequence: 2, root_sha3_512: second.root_sha3_512 } };
const archive = createEvidenceArchive(capsule, [
  { record: first, witnesses: firstWitnesses }, { record: second, witnesses: secondWitnesses }
], policy);
if (!verifyEvidenceArchive(archive, policy).verified) throw new Error("The reference vector does not verify");

const archiveFile = `${canonicalJSONStringify(archive)}\n`;
const expected = {
  protocol: "aml-evidence-archive-vector/1",
  archive_file_sha256: crypto.createHash("sha256").update(archiveFile).digest("hex"),
  archive_root_sha3_512: archive.root_sha3_512,
  capsule_sha256: capsule.digests.sha256,
  capsule_sha512: capsule.digests.sha512,
  renewal_roots_sha3_512: [first.root_sha3_512, second.root_sha3_512],
  witness_fingerprints_sha256: fingerprints,
  expected: { verified: true, renewal_count: 2, freshness_bound: true, policy_hint_trusted: false }
};
const files = {
  "archive.json": archiveFile,
  "trusted-policy.json": `${canonicalJSONStringify(policy)}\n`,
  "expected.json": `${canonicalJSONStringify(expected)}\n`
};

if (process.argv[2] === "--write") {
  fs.mkdirSync(root, { recursive: true });
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, name), content);
} else if (process.argv.length !== 2) {
  throw new Error("Usage: node scripts/check-evidence-archive-vector.mjs [--write]");
} else {
  for (const [name, content] of Object.entries(files)) {
    if (!fs.existsSync(path.join(root, name)) || fs.readFileSync(path.join(root, name), "utf8") !== content) {
      throw new Error(`Archive vector drift: ${name}`);
    }
  }
}
process.stdout.write(`${JSON.stringify({ checked: Object.keys(files), archive_root_sha3_512: expected.archive_root_sha3_512 })}\n`);
