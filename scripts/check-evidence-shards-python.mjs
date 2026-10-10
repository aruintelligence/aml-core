import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { createEvidenceShards } from "../runtime/evidenceShards.js";
import { createEvidenceMigration } from "../runtime/evidenceMigration.js";
import { createEvidenceArchive } from "../runtime/evidenceArchive.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { createEvidenceRenewal, attestEvidenceRenewal } from "../runtime/evidenceRenewal.js";
import { signExecutionReceipt } from "../compiler/accountablePipeline.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-shards-python-"));
const verifier = path.resolve("independent/python/recover_evidence_shards.py");
const vector = "independent/vectors/shards-v1";
const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(`${vector}/share-${index}.json`, "utf8")));
const policy = JSON.parse(fs.readFileSync("independent/vectors/archive-v1/trusted-policy.json", "utf8"));
const migration = fs.readFileSync("independent/vectors/migration-v1/migration.json");
const archive = JSON.parse(fs.readFileSync("independent/vectors/archive-v1/archive.json", "utf8"));
const hash = (algorithm, data) => crypto.createHash(algorithm).update(data).digest("hex");

function run(name, selected, trust, expected, reason = null, destination = null) {
  const files = selected.map((share, index) => {
    const file = path.join(directory, `${name}-share-${index}.json`);
    fs.writeFileSync(file, JSON.stringify(share));
    return file;
  });
  const trustFile = path.join(directory, `${name}-trust.json`);
  const output = destination ?? path.join(directory, `${name}-recovered.json`);
  fs.writeFileSync(trustFile, JSON.stringify(trust));
  const args = [verifier, ...files, trustFile, output];
  const result = spawnSync("python3", args, { encoding: "utf8" });
  if (result.error) throw result.error;
  const report = JSON.parse(result.stdout);
  if (report.recovered !== expected || result.status !== (expected ? 0 : 1) ||
      (reason && report.reason !== reason)) {
    throw new Error(`${name}: unexpected Python result ${result.stdout} ${result.stderr}`);
  }
  if (!expected && fs.existsSync(output) && destination === null) throw new Error(`${name}: failed recovery wrote a file`);
  return { report, output, args };
}

try {
  const results = [];
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    const name = `pair-${pair.join("")}`;
    const { report, output } = run(name, pair.map(index => shares[index]), policy, true);
    if (!fs.readFileSync(output).equals(migration) || report.valid_pairs !== 1) throw new Error(`${name}: wrong recovered bytes`);
    results.push({ name, recovered: true });
  }
  const damaged = structuredClone(shares);
  damaged[0].segment_base64 = "broken";
  const recovered = run("one-damaged", damaged, policy, true);
  if (!fs.readFileSync(recovered.output).equals(migration)) throw new Error("one-damaged: wrong bytes");
  results.push({ name: "one-damaged", recovered: true });
  damaged[1].segment_base64 = "broken";
  results.push({ name: "two-damaged", reason: run("two-damaged", damaged, policy, false, "insufficient_valid_shares").report.reason });

  const changed = structuredClone(shares[1]);
  const bytes = Buffer.from(changed.segment_base64, "base64");
  bytes[0] ^= 1;
  changed.segment_base64 = bytes.toString("base64");
  changed.segment_sha512 = hash("sha512", bytes);
  const { root_sha3_512, ...payload } = changed;
  changed.root_sha3_512 = hash("sha3-512", canonicalJSONStringify(payload));
  results.push({ name: "self-rehashed-corruption", reason: run("corrupt", [shares[0], changed], policy,
    false, "no_trusted_recovery_pair").report.reason });
  results.push({ name: "rollback", reason: run("rollback", [shares[0], shares[2]],
    { ...policy, accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } },
    false, "no_trusted_recovery_pair").report.reason });

  const first = run("overwrite", [shares[0], shares[1]], policy, true);
  const second = spawnSync("python3", first.args, { encoding: "utf8" });
  if (second.status !== 1 || JSON.parse(second.stdout).recovered) throw new Error("Python overwrote a recovered file");
  results.push({ name: "overwrite-refused", recovered: false });

  const privateKey = crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
  const originalCapsule = JSON.parse(Buffer.from(archive.capsule_base64, "base64").toString("utf8"));
  const receipt = signExecutionReceipt(originalCapsule.receipt, privateKey,
    { signer: "synthetic", timestamp: "2026-10-10T03:00:00.000Z" });
  const capsule = createEvidenceCapsule(receipt);
  const record = createEvidenceRenewal(capsule, { sequence: 1, created_at: "2026-10-10T04:00:00.000Z" });
  const witness = attestEvidenceRenewal(record, privateKey, { signer: "synthetic", signed_at: record.created_at });
  const witnessTrust = { threshold: 1, trusted_fingerprints: [witness.public_key_fingerprint_sha256] };
  const signedArchive = createEvidenceArchive(capsule, [{ record, witnesses: [witness] }], witnessTrust);
  const signedTrust = { ...witnessTrust, trusted_receipt_fingerprints: [receipt.signature.public_key_sha256] };
  const signedShares = createEvidenceShards(createEvidenceMigration(signedArchive, signedTrust), signedTrust);
  results.push({ name: "signed-receipt", recovered: run("signed", signedShares.slice(1), signedTrust, true).report.recovered });
  results.push({ name: "receipt-trust-required", reason: run("receipt-untrusted", signedShares.slice(1),
    witnessTrust, false, "no_trusted_recovery_pair").report.reason });
  results.push({ name: "receipt-revoked", reason: run("receipt-revoked", signedShares.slice(1),
    { ...signedTrust, revoked_receipt_fingerprints: signedTrust.trusted_receipt_fingerprints },
    false, "no_trusted_recovery_pair").report.reason });

  process.stdout.write(`${JSON.stringify({ protocol: "aml-shards-cross-runtime-check/1", passed: true, results }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
