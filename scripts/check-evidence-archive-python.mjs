import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { executeAccountableIntent, signExecutionReceipt } from "../compiler/accountablePipeline.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { createEvidenceRenewal, attestEvidenceRenewal } from "../runtime/evidenceRenewal.js";
import { createEvidenceArchive, verifyEvidenceArchive } from "../runtime/evidenceArchive.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-archive-python-"));
const verifier = path.resolve("independent/python/verify_evidence_archive.py");
const intent = JSON.parse(fs.readFileSync("pilots/enterprise-30min/intent-allowed.json", "utf8"));
const capsule = createEvidenceCapsule(executeAccountableIntent(intent, { profile: "human_first", timestamp: "2026-10-10T00:00:00.000Z" }));
const keys = Array.from({ length: 3 }, () => crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }));
const first = createEvidenceRenewal(capsule, { sequence: 1, created_at: "2026-10-10T01:00:00.000Z" });
const second = createEvidenceRenewal(capsule, { sequence: 2, previous_root_sha3_512: first.root_sha3_512, created_at: "2026-10-10T02:00:00.000Z" });
const attest = (record, key, signer) => attestEvidenceRenewal(record, key, { signer, signed_at: record.created_at });
const firstWitnesses = [attest(first, keys[0], "first"), attest(first, keys[1], "second")];
const secondWitnesses = [attest(second, keys[1], "second"), attest(second, keys[2], "rotated")];
const entries = [{ record: first, witnesses: firstWitnesses }, { record: second, witnesses: secondWitnesses }];
const fingerprints = [...firstWitnesses.map(w => w.public_key_fingerprint_sha256), secondWitnesses[1].public_key_fingerprint_sha256];
const policy = { threshold: 2, trusted_fingerprints: fingerprints,
  trusted_fingerprints_by_sequence: { 1: fingerprints.slice(0, 2), 2: fingerprints.slice(1) },
  accepted_head: { sequence: 2, root_sha3_512: second.root_sha3_512 } };

// Export a fixture when sandboxed runtimes disallow Node child processes.
if (process.argv[2] === "--emit-fixture") {
  const output = process.argv[3];
  if (!output) throw new Error("Provide a fixture directory");
  fs.mkdirSync(output, { recursive: true });
  fs.writeFileSync(path.join(output, "archive.json"), JSON.stringify(createEvidenceArchive(capsule, entries, policy)));
  fs.writeFileSync(path.join(output, "trusted-policy.json"), JSON.stringify(policy));
  process.exit(0);
}

function rehash(archive) {
  const { root_sha3_512, ...payload } = archive;
  archive.root_sha3_512 = crypto.createHash("sha3-512").update(canonicalJSONStringify(payload)).digest("hex");
}

function check(name, archive, trusted, expected, reason = null) {
  const archiveFile = path.join(directory, `${name}-archive.json`);
  const policyFile = path.join(directory, `${name}-policy.json`);
  fs.writeFileSync(archiveFile, typeof archive === "string" ? archive : JSON.stringify(archive));
  fs.writeFileSync(policyFile, JSON.stringify(trusted));
  const result = spawnSync("python3", [verifier, archiveFile, policyFile], { encoding: "utf8" });
  if (result.error) throw result.error;
  const report = JSON.parse(result.stdout);
  if (report.verified !== expected || result.status !== (expected ? 0 : 1) || (reason && report.reason !== reason)) {
    throw new Error(`${name}: unexpected Python result ${result.stdout} ${result.stderr}`);
  }
  return { name, verified: report.verified, reason: report.reason ?? null };
}

try {
  const archive = createEvidenceArchive(capsule, entries, policy);
  if (!verifyEvidenceArchive(archive, policy).verified) throw new Error("JavaScript baseline failed");
  const results = [check("valid-rotated-quorum", archive, policy, true)];

  const wrongTrust = { ...policy, trusted_fingerprints_by_sequence: { 1: fingerprints.slice(0, 2), 2: fingerprints.slice(0, 2) } };
  results.push(check("wrong-rotated-trust", archive, wrongTrust, false, "quorum_not_met"));

  const revoked = { ...policy, revoked_fingerprints: [fingerprints[2]] };
  results.push(check("revoked-witness", archive, revoked, false, "quorum_not_met"));

  const rolledBack = createEvidenceArchive(capsule, entries.slice(0, 1), { ...policy,
    accepted_head: { sequence: 1, root_sha3_512: first.root_sha3_512 } });
  results.push(check("rollback-against-remembered-head", rolledBack, policy, false, "accepted_head_missing_or_forked"));

  const swapped = structuredClone(archive);
  swapped.capsule_base64 = archive.renewals_base64;
  rehash(swapped);
  results.push(check("swapped-component", swapped, policy, false, "component_digest_mismatch"));

  const noncanonical = structuredClone(archive);
  noncanonical.policy_hint_base64 = Buffer.from(JSON.stringify(policy, null, 2)).toString("base64");
  noncanonical.manifest.policy_hint_sha3_512 = crypto.createHash("sha3-512").update(Buffer.from(noncanonical.policy_hint_base64, "base64")).digest("hex");
  rehash(noncanonical);
  results.push(check("noncanonical-component", noncanonical, policy, false, "noncanonical_json_or_unsupported_numeric_serialization"));

  const forged = structuredClone(archive);
  const alteredCapsule = structuredClone(capsule);
  alteredCapsule.receipt.selected_render.html = "changed after receipt";
  const { digests, ...alteredPayload } = alteredCapsule;
  const alteredBytes = canonicalJSONStringify(alteredPayload);
  alteredCapsule.digests = Object.fromEntries(["sha256", "sha512"].map(algorithm =>
    [algorithm, crypto.createHash(algorithm).update(alteredBytes).digest("hex")]));
  forged.capsule_base64 = Buffer.from(canonicalJSONStringify(alteredCapsule)).toString("base64");
  forged.manifest.capsule_sha3_512 = crypto.createHash("sha3-512").update(Buffer.from(forged.capsule_base64, "base64")).digest("hex");
  rehash(forged);
  results.push(check("rehashed-invalid-receipt", forged, policy, false, "invalid_or_unsupported_capsule"));

  const duplicate = JSON.stringify(archive).replace('"protocol":"aml-evidence-archive/1"', '"protocol":"aml-evidence-archive/1","protocol":"aml-evidence-archive/1"');
  results.push(check("duplicate-json-key", duplicate, policy, false, "duplicate JSON key"));

  const signedReceipt = signExecutionReceipt(executeAccountableIntent(intent, { profile: "human_first", timestamp: "2026-10-10T00:00:00.000Z" }), keys[0],
    { signer: "synthetic-receipt", timestamp: "2026-10-10T00:30:00.000Z" });
  const signedCapsule = createEvidenceCapsule(signedReceipt);
  const signedRecord = createEvidenceRenewal(signedCapsule, { sequence: 1, created_at: "2026-10-10T01:00:00.000Z" });
  const signedWitness = attest(signedRecord, keys[0], "synthetic");
  const signedPolicy = { threshold: 1, trusted_fingerprints: [signedWitness.public_key_fingerprint_sha256],
    trusted_receipt_fingerprints: [signedReceipt.signature.public_key_sha256] };
  const signedArchive = createEvidenceArchive(signedCapsule, [{ record: signedRecord, witnesses: [signedWitness] }], signedPolicy);
  results.push(check("signed-archive-valid", signedArchive, signedPolicy, true));
  results.push(check("signed-archive-trust-missing", signedArchive, { threshold: 1, trusted_fingerprints: signedPolicy.trusted_fingerprints }, false, "external_receipt_trust_required"));
  results.push(check("signed-archive-key-revoked", signedArchive,
    { ...signedPolicy, revoked_receipt_fingerprints: signedPolicy.trusted_receipt_fingerprints }, false, "invalid_or_unsupported_capsule"));

  process.stdout.write(`${JSON.stringify({ protocol: "aml-archive-cross-runtime-check/1", passed: true, results }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
