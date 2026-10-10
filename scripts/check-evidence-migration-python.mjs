import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createEvidenceMigration } from "../runtime/evidenceMigration.js";
import { createEvidenceArchive } from "../runtime/evidenceArchive.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { createEvidenceRenewal, attestEvidenceRenewal } from "../runtime/evidenceRenewal.js";
import { signExecutionReceipt } from "../compiler/accountablePipeline.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-migration-python-"));
const verifier = path.resolve("independent/python/verify_evidence_migration.py");
const v1 = path.resolve("independent/vectors/archive-v1");
const source = JSON.parse(fs.readFileSync(path.join(v1, "archive.json"), "utf8"));
const policy = JSON.parse(fs.readFileSync(path.join(v1, "trusted-policy.json"), "utf8"));
const digest = (algorithm, data) => crypto.createHash(algorithm).update(data).digest("hex");

function rehash(handoff) {
  const { root_sha3_512, root_sha512, ...payload } = handoff;
  const bytes = canonicalJSONStringify(payload);
  handoff.root_sha3_512 = digest("sha3-512", bytes);
  handoff.root_sha512 = digest("sha512", bytes);
}

function check(name, handoff, trusted, expected, reason = null, action = null) {
  const handoffPath = path.join(directory, `${name}-handoff.json`);
  const trustPath = path.join(directory, `${name}-trust.json`);
  const destination = path.join(directory, `${name}-recovered.json`);
  fs.writeFileSync(handoffPath, typeof handoff === "string" ? handoff : JSON.stringify(handoff));
  fs.writeFileSync(trustPath, JSON.stringify(trusted));
  const args = action === "recover" ? [verifier, "recover", handoffPath, trustPath, destination] : [verifier, handoffPath, trustPath];
  const result = spawnSync("python3", args, { encoding: "utf8" });
  if (result.error) throw result.error;
  const report = JSON.parse(result.stdout);
  if (report.verified !== expected || result.status !== (expected ? 0 : 1) || (reason && report.reason !== reason)) {
    throw new Error(`${name}: unexpected Python result ${result.stdout} ${result.stderr}`);
  }
  return { name, report, destination, args };
}

try {
  const frozen = JSON.parse(fs.readFileSync("independent/vectors/migration-v1/migration.json", "utf8"));
  const results = [];
  const valid = check("frozen-vector", frozen, policy, true);
  if (!valid.report.component_equivalent || !valid.report.freshness_bound) throw new Error("Frozen vector lost source or freshness binding");
  results.push({ name: valid.name, verified: true });
  const recovered = check("recover", frozen, policy, true, null, "recover");
  if (!fs.readFileSync(recovered.destination).equals(fs.readFileSync(path.join(v1, "archive.json")))) {
    throw new Error("Python did not recover the exact canonical v1 archive file");
  }
  const second = spawnSync("python3", recovered.args, { encoding: "utf8" });
  if (second.status !== 1 || JSON.parse(second.stdout).verified) throw new Error("Python recovery overwrote an existing file");
  results.push({ name: "recover-without-overwrite", verified: true });

  results.push({ name: "untrusted-witness", reason: check("untrusted-witness", frozen,
    { ...policy, trusted_fingerprints: ["f".repeat(64)], trusted_fingerprints_by_sequence: null }, false, "quorum_not_met").report.reason });
  results.push({ name: "rollback", reason: check("rollback", frozen,
    { ...policy, accepted_head: { sequence: 2, root_sha3_512: "a".repeat(128) } }, false,
    "accepted_head_missing_or_forked").report.reason });

  const swapped = structuredClone(frozen);
  const replacement = Buffer.from(canonicalJSONStringify({ note: "replacement" }));
  swapped.policy_hint_base64 = replacement.toString("base64");
  swapped.manifest.policy_hint_sha3_512 = digest("sha3-512", replacement);
  swapped.manifest.policy_hint_sha512 = digest("sha512", replacement);
  rehash(swapped);
  results.push({ name: "rehash-cannot-hide-target-change", reason: check("swapped", swapped, policy, false,
    "component_equivalence_mismatch").report.reason });

  const duplicated = JSON.stringify(frozen).replace('"protocol":"aml-evidence-migration/1"',
    '"protocol":"aml-evidence-migration/1","protocol":"aml-evidence-migration/1"');
  results.push({ name: "duplicate-json-key", reason: check("duplicate", duplicated, policy, false, "duplicate JSON key").report.reason });

  const privateKey = crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
  const originalCapsule = JSON.parse(Buffer.from(source.capsule_base64, "base64").toString("utf8"));
  const signedReceipt = signExecutionReceipt(originalCapsule.receipt, privateKey,
    { signer: "synthetic", timestamp: "2026-10-10T03:00:00.000Z" });
  const capsule = createEvidenceCapsule(signedReceipt);
  const record = createEvidenceRenewal(capsule, { sequence: 1, created_at: "2026-10-10T04:00:00.000Z" });
  const witness = attestEvidenceRenewal(record, privateKey, { signer: "synthetic", signed_at: record.created_at });
  const witnessTrust = { threshold: 1, trusted_fingerprints: [witness.public_key_fingerprint_sha256] };
  const archive = createEvidenceArchive(capsule, [{ record, witnesses: [witness] }], witnessTrust);
  const trusted = { ...witnessTrust, trusted_receipt_fingerprints: [signedReceipt.signature.public_key_sha256] };
  const signed = createEvidenceMigration(archive, trusted);
  results.push({ name: "signed-receipt", verified: check("signed", signed, trusted, true).report.verified });
  results.push({ name: "receipt-trust-required", reason: check("receipt-untrusted", signed, witnessTrust, false,
    "external_receipt_trust_required").report.reason });
  results.push({ name: "receipt-revoked", reason: check("receipt-revoked", signed,
    { ...trusted, revoked_receipt_fingerprints: trusted.trusted_receipt_fingerprints }, false,
    "invalid_or_unsupported_capsule").report.reason });

  process.stdout.write(`${JSON.stringify({ protocol: "aml-migration-cross-runtime-check/1", passed: true, results }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
