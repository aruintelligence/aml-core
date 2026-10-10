import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { executeAccountableIntent, signExecutionReceipt } from "../compiler/accountablePipeline.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-capsule-python-"));
const verifier = path.resolve("independent/python/verify_evidence_capsule.py");
const intent = JSON.parse(fs.readFileSync("pilots/enterprise-30min/intent-allowed.json", "utf8"));
const receipt = executeAccountableIntent(intent, { profile: "human_first", timestamp: "2026-10-10T00:00:00.000Z" });

function rehash(capsule) {
  const { digests, ...payload } = capsule;
  const bytes = canonicalJSONStringify(payload);
  capsule.digests = Object.fromEntries(["sha256", "sha512"].map(algorithm => [algorithm, crypto.createHash(algorithm).update(bytes).digest("hex")]));
}

function check(name, content, expected, policy = null) {
  const file = path.join(directory, `${name}.json`);
  fs.writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content));
  const args = [verifier, file];
  if (policy) {
    const policyFile = path.join(directory, `${name}-policy.json`);
    fs.writeFileSync(policyFile, JSON.stringify(policy));
    args.push(policyFile);
  }
  const result = spawnSync("python3", args, { encoding: "utf8" });
  if (result.error) throw result.error;
  const report = JSON.parse(result.stdout);
  if (report.verified !== expected || result.status !== (expected ? 0 : 1)) {
    throw new Error(`${name}: unexpected Python result ${result.stdout} ${result.stderr}`);
  }
  return { name, verified: report.verified };
}

try {
  const original = createEvidenceCapsule(receipt);
  const results = [check("valid", original, true)];

  const forged = structuredClone(original);
  forged.receipt.selected_render.html = "tampered";
  rehash(forged);
  results.push(check("inner-binding-mutated", forged, false));

  const summary = structuredClone(original);
  summary.summary.allowed = 99;
  rehash(summary);
  results.push(check("summary-mutated", summary, false));

  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const signed = signExecutionReceipt(receipt, privateKey.export({ type: "pkcs8", format: "pem" }),
    { signer: "synthetic", timestamp: "2026-10-10T01:00:00.000Z" });
  const signedCapsule = createEvidenceCapsule(signed);
  const signedPolicy = { trusted_receipt_fingerprints: [signed.signature.public_key_sha256] };
  results.push(check("signed-external-trust-required", signedCapsule, false));
  results.push(check("signed-valid", signedCapsule, true, signedPolicy));
  results.push(check("signed-wrong-trust", signedCapsule, false, { trusted_receipt_fingerprints: ["f".repeat(64)] }));
  results.push(check("signed-revoked", signedCapsule, false, { ...signedPolicy, revoked_receipt_fingerprints: signedPolicy.trusted_receipt_fingerprints }));
  const forgedSigner = structuredClone(signedCapsule);
  forgedSigner.receipt.signature.signer = "forged";
  rehash(forgedSigner);
  results.push(check("signed-attribution-mutated", forgedSigner, false, signedPolicy));
  results.push(check("duplicate-key", JSON.stringify(original).replace('"protocol":"aml-evidence-capsule/1"', '"protocol":"aml-evidence-capsule/1","protocol":"aml-evidence-capsule/1"'), false));

  process.stdout.write(`${JSON.stringify({ protocol: "aml-capsule-cross-runtime-check/1", passed: true, results }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
