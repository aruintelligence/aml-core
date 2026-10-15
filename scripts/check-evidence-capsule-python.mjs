import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { executeAccountableIntent, signExecutionReceipt, verifyExecutionReceipt } from "../compiler/accountablePipeline.js";
import { createAttentionLedger, consumeAttention } from "../runtime/attentionLedger.js";
import { createEvidenceCapsule, verifyEvidenceCapsule } from "../runtime/evidenceCapsule.js";
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

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().filter(key => value[key] !== undefined)
      .map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hashValue(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

function rehashAudit(receipt) {
  let previous = null;
  for (const entry of receipt.runtime_audit_stream.entries) {
    entry.previous_hash = previous;
    const { entry_hash, ...core } = entry;
    entry.entry_hash = hashValue(core);
    previous = entry.entry_hash;
  }
  receipt.audit_stream_sha256 = hashValue(receipt.runtime_audit_stream);
}

function rebindLedgerAudit(receipt) {
  const selected = receipt.runtime_audit_stream.entries[3].payload;
  selected.attention_ledger_remaining = receipt.attention_ledger.remaining;
  selected.attention_ledger_consumed = receipt.attention_ledger.consumed;
  rehashAudit(receipt);
}

function receiptWithLedger(base, ledger) {
  const updated = structuredClone(base);
  updated.attention_ledger = ledger;
  updated.attention_ledger_sha256 = hashValue(ledger);
  rebindLedgerAudit(updated);
  const payload = { ...updated };
  delete payload.receipt_sha256;
  updated.receipt_sha256 = hashValue(payload);
  return updated;
}

function signModifiedReceipt(receipt, privateKey) {
  const payload = { ...receipt };
  delete payload.receipt_sha256;
  delete payload.signature;
  receipt.receipt_sha256 = hashValue(payload);
  const { signature } = receipt;
  const material = { protocol: "ĀML Execution Receipt Attestation", version: "1.1", algorithm: "Ed25519",
    receipt_sha256: receipt.receipt_sha256, signer: signature.signer, signed_at: signature.signed_at };
  signature.signature_base64 = crypto.sign(null, Buffer.from(stableStringify(material)), privateKey).toString("base64");
}

function resign(receipt, privateKey) {
  receipt.attention_ledger_sha256 = hashValue(receipt.attention_ledger);
  rebindLedgerAudit(receipt);
  signModifiedReceipt(receipt, privateKey);
}

function check(name, content, expected, policy = null, reasonIncludes = null, expectedChecks = null) {
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
  if (report.verified !== expected || result.status !== (expected ? 0 : 1) ||
      (reasonIncludes && !report.reason?.includes(reasonIncludes)) ||
      (expectedChecks && Object.entries(expectedChecks).some(([key, value]) => report.checks?.[key] !== value)) ||
      (expected && policy && report.attribution_bound !== true)) {
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
  const changedIntent = structuredClone(signedCapsule);
  changedIntent.receipt.intent.audit_probe = "different declaration";
  changedIntent.receipt.intent_sha256 = hashValue(changedIntent.receipt.intent);
  signModifiedReceipt(changedIntent.receipt, privateKey);
  changedIntent.summary.receipt_sha256 = changedIntent.receipt.receipt_sha256;
  rehash(changedIntent);
  if (verifyEvidenceCapsule(changedIntent).verified) throw new Error("JavaScript accepted a signed receipt with a stale audit intent");
  results.push(check("signed-audit-intent-binding-rejected", changedIntent, false, signedPolicy,
    null, { receipt_hash: true, intent: true, audit: true, audit_binding: false, signature: true, summary: true }));

  const changedAudit = structuredClone(signedCapsule);
  changedAudit.receipt.runtime_audit_stream.entries[3].payload.attention_ledger_consumed = 999;
  rehashAudit(changedAudit.receipt);
  signModifiedReceipt(changedAudit.receipt, privateKey);
  changedAudit.summary.receipt_sha256 = changedAudit.receipt.receipt_sha256;
  rehash(changedAudit);
  if (verifyEvidenceCapsule(changedAudit).verified) throw new Error("JavaScript accepted a signed receipt with a conflicting audit event");
  results.push(check("signed-audit-ledger-binding-rejected", changedAudit, false, signedPolicy,
    null, { receipt_hash: true, audit: true, audit_binding: false, ledger: true, signature: true, summary: true }));
  for (const field of ["runtime_audit_stream", "attention_ledger"]) {
    const omitted = structuredClone(signedCapsule);
    delete omitted.receipt[field];
    signModifiedReceipt(omitted.receipt, privateKey);
    omitted.summary.receipt_sha256 = omitted.receipt.receipt_sha256;
    rehash(omitted);
    if (verifyEvidenceCapsule(omitted).verified) throw new Error(`JavaScript accepted a receipt missing ${field}`);
    results.push(check(`signed-missing-${field}-rejected`, omitted, false, signedPolicy, field));
  }
  const nonArrayAudit = structuredClone(signedCapsule);
  nonArrayAudit.receipt.runtime_audit_stream.entries = "";
  nonArrayAudit.receipt.audit_stream_sha256 = hashValue(nonArrayAudit.receipt.runtime_audit_stream);
  signModifiedReceipt(nonArrayAudit.receipt, privateKey);
  nonArrayAudit.summary.receipt_sha256 = nonArrayAudit.receipt.receipt_sha256;
  rehash(nonArrayAudit);
  if (verifyEvidenceCapsule(nonArrayAudit).verified) throw new Error("JavaScript accepted non-array audit entries");
  results.push(check("signed-non-array-audit-rejected", nonArrayAudit, false, signedPolicy,
    null, { receipt_hash: true, audit: false, signature: true, summary: true }));
  const alteredEncoding = structuredClone(signedCapsule);
  alteredEncoding.receipt.signature.signature_base64 += "!!!!";
  rehash(alteredEncoding);
  if (verifyEvidenceCapsule(alteredEncoding).verified) throw new Error("JavaScript accepted a noncanonical signature");
  results.push(check("signed-noncanonical-base64-rejected", alteredEncoding, false, signedPolicy,
    null, { receipt_hash: true, signature: false }));
  for (const [type, options] of [["rsa", { modulusLength: 2048 }], ["ec", { namedCurve: "prime256v1" }]]) {
    const foreign = crypto.generateKeyPairSync(type, options);
    const mislabeled = structuredClone(signedCapsule);
    const attestation = mislabeled.receipt.signature;
    const der = foreign.publicKey.export({ type: "spki", format: "der" });
    attestation.public_key_pem = foreign.publicKey.export({ type: "spki", format: "pem" }).toString();
    attestation.public_key_sha256 = crypto.createHash("sha256").update(der).digest("hex");
    const material = { protocol: attestation.protocol, version: attestation.version,
      algorithm: attestation.algorithm, receipt_sha256: mislabeled.receipt.receipt_sha256,
      signer: attestation.signer, signed_at: attestation.signed_at };
    attestation.signature_base64 = crypto.sign(null, Buffer.from(stableStringify(material)),
      foreign.privateKey).toString("base64");
    rehash(mislabeled);
    if (verifyEvidenceCapsule(mislabeled).verified) throw new Error(`JavaScript accepted ${type} as Ed25519`);
    results.push(check(`signed-${type}-mislabeled-ed25519-rejected`, mislabeled, false,
      { trusted_receipt_fingerprints: [attestation.public_key_sha256] },
      null, { receipt_hash: true, signature: false }));
  }
  for (const [name, value] of [
    ["small-exponent", 1e-7], ["fixed-boundary", 1e-6],
    ["negative-fraction", -0.0000015], ["negative-zero", -0],
    ["minimum-subnormal", Number.MIN_VALUE],
    ["maximum-safe-integer", Number.MAX_SAFE_INTEGER],
    ["first-beyond-safe", 2 ** 53], ["rounded-large-integer", 1000000000000000100],
    ["large-fixed", 1e20], ["large-exponent-boundary", 1e21],
    ["large-exponent", 1e100], ["maximum-finite", Number.MAX_VALUE],
    ["negative-large", -1e250]
  ]) {
    const numericReceipt = executeAccountableIntent({ ...intent, numeric_probe: value },
      { profile: "human_first", timestamp: "2026-10-10T00:00:00.000Z" });
    const numericSignature = signExecutionReceipt(numericReceipt, privateKey.export({ type: "pkcs8", format: "pem" }),
      { signer: "synthetic", timestamp: "2026-10-10T01:00:00.000Z" });
    const numericCapsule = createEvidenceCapsule(numericSignature);
    results.push(check(`signed-numeric-${name}`, numericCapsule, true, signedPolicy));
    if (name === "small-exponent") {
      const tampered = structuredClone(numericCapsule);
      tampered.receipt.intent.numeric_probe = 2e-7;
      rehash(tampered);
      results.push(check("signed-numeric-tampered", tampered, false, signedPolicy));
    }
    if (name === "first-beyond-safe") {
      const tampered = structuredClone(numericCapsule);
      tampered.receipt.intent.numeric_probe = 2 ** 53 + 2;
      rehash(tampered);
      results.push(check("signed-large-number-tampered", tampered, false, signedPolicy));
      const serialized = JSON.stringify(numericCapsule);
      const alias = serialized.replace('"numeric_probe":9007199254740992', '"numeric_probe":9007199254740993');
      if (alias === serialized || JSON.parse(alias).receipt.intent.numeric_probe !== value) {
        throw new Error("Numeric alias fixture does not preserve the JavaScript Number");
      }
      results.push(check("signed-large-number-same-value-alias", alias, true, signedPolicy));
      const nonFinite = serialized.replace('"numeric_probe":9007199254740992', '"numeric_probe":1e400');
      results.push(check("signed-nonfinite-json-rejected", nonFinite, false, signedPolicy,
        "unsupported non-finite JSON number"));
    }
  }
  const largeBudgetContext = JSON.parse(fs.readFileSync("pilots/enterprise-30min/context-denied.json", "utf8"));
  largeBudgetContext.attention_budget_remaining = 2 ** 53;
  const largeBudgetReceipt = executeAccountableIntent(intent,
    { profile: "human_first", context: largeBudgetContext, timestamp: "2026-10-10T00:00:00.000Z" });
  const largeBudgetSignature = signExecutionReceipt(largeBudgetReceipt, privateKey.export({ type: "pkcs8", format: "pem" }),
    { signer: "synthetic", timestamp: "2026-10-10T01:00:00.000Z" });
  results.push(check("signed-large-attention-budget", createEvidenceCapsule(largeBudgetSignature), true, signedPolicy));
  const roundingLedger = createAttentionLedger(null);
  for (const amount of [Number.MAX_SAFE_INTEGER, 1, 1]) consumeAttention(roundingLedger, amount);
  if (roundingLedger.consumed !== 2 ** 53) throw new Error("Ledger rounding fixture changed");
  const roundingReceipt = receiptWithLedger(receipt, roundingLedger);
  if (!verifyExecutionReceipt(roundingReceipt).verified) throw new Error("JavaScript rejected the rounding fixture");
  const roundingSignature = signExecutionReceipt(roundingReceipt, privateKey.export({ type: "pkcs8", format: "pem" }),
    { signer: "synthetic", timestamp: "2026-10-10T01:00:00.000Z" });
  results.push(check("signed-ledger-binary64-sum", createEvidenceCapsule(roundingSignature), true, signedPolicy));
  const roundingSource = JSON.stringify(createEvidenceCapsule(roundingSignature));
  const negativeZeroSequence = roundingSource.replace('"sequence":0', '"sequence":-0');
  if (negativeZeroSequence === roundingSource ||
      !verifyExecutionReceipt(JSON.parse(negativeZeroSequence).receipt).verified) {
    throw new Error("Negative-zero sequence fixture changed JavaScript verification");
  }
  results.push(check("signed-negative-zero-sequence", negativeZeroSequence, true, signedPolicy));

  const oneLedger = createAttentionLedger(1);
  const oneSignature = signExecutionReceipt(receiptWithLedger(receipt, oneLedger),
    privateKey.export({ type: "pkcs8", format: "pem" }),
    { signer: "synthetic", timestamp: "2026-10-10T01:00:00.000Z" });
  const forgedBalance = createEvidenceCapsule(oneSignature);
  forgedBalance.receipt.attention_ledger.remaining = true;
  resign(forgedBalance.receipt, privateKey);
  forgedBalance.summary.receipt_sha256 = forgedBalance.receipt.receipt_sha256;
  rehash(forgedBalance);
  if (verifyExecutionReceipt(forgedBalance.receipt).verified) throw new Error("JavaScript accepted a boolean balance");
  results.push(check("signed-ledger-boolean-balance-rejected", forgedBalance, false, signedPolicy,
    null, { receipt_hash: true, signature: true, ledger: false, summary: true }));

  const zeroSignature = signExecutionReceipt(receiptWithLedger(receipt, createAttentionLedger(0)),
    privateKey.export({ type: "pkcs8", format: "pem" }),
    { signer: "synthetic", timestamp: "2026-10-10T01:00:00.000Z" });
  const zeroSource = JSON.stringify(createEvidenceCapsule(zeroSignature));
  const negativeZero = zeroSource.replace('"remaining":0', '"remaining":-0');
  if (negativeZero === zeroSource || verifyExecutionReceipt(JSON.parse(negativeZero).receipt).verified) {
    throw new Error("Negative-zero balance fixture does not diverge from JavaScript");
  }
  results.push(check("signed-ledger-negative-zero-balance-rejected", negativeZero, false, signedPolicy,
    null, { receipt_hash: true, signature: true, ledger: false, summary: true }));
  for (const [name, key_probe] of [
    ["array-index-keys", { "10": "ten", "2": "two", "01": "leading", "0": "zero",
      "4294967294": "last index", "4294967295": "ordinary key" }],
    ["utf16-key-order", { "\uE000": "private use", "\u{1F4A1}": "astral" }],
    ["lone-surrogates", { "\uD800": "lone key", text: "before\uDC00after", control: "\b\n\u2028" }]
  ]) {
    const keyedReceipt = executeAccountableIntent({ ...intent, key_probe },
      { profile: "human_first", timestamp: "2026-10-10T00:00:00.000Z" });
    const keyedSignature = signExecutionReceipt(keyedReceipt, privateKey.export({ type: "pkcs8", format: "pem" }),
      { signer: "synthetic", timestamp: "2026-10-10T01:00:00.000Z" });
    const keyedCapsule = createEvidenceCapsule(keyedSignature);
    results.push(check(`signed-${name}`, keyedCapsule, true, signedPolicy));
    if (name === "array-index-keys") {
      const tampered = structuredClone(keyedCapsule);
      tampered.receipt.intent.key_probe["2"] = "changed";
      rehash(tampered);
      results.push(check("signed-array-index-key-tampered", tampered, false, signedPolicy));
    }
  }
  results.push(check("signed-wrong-trust", signedCapsule, false, { trusted_receipt_fingerprints: ["f".repeat(64)] }));
  results.push(check("signed-revoked", signedCapsule, false, { ...signedPolicy, revoked_receipt_fingerprints: signedPolicy.trusted_receipt_fingerprints }));
  const forgedSigner = structuredClone(signedCapsule);
  forgedSigner.receipt.signature.signer = "forged";
  rehash(forgedSigner);
  results.push(check("signed-attribution-mutated", forgedSigner, false, signedPolicy));
  results.push(check("duplicate-key", JSON.stringify(original).replace('"protocol":"aml-evidence-capsule/1"', '"protocol":"aml-evidence-capsule/1","protocol":"aml-evidence-capsule/1"'), false));
  results.push(check("duplicate-escaped-key", JSON.stringify(original).replace('"protocol":"aml-evidence-capsule/1"', '"protocol":"aml-evidence-capsule/1","\\u0070rotocol":"aml-evidence-capsule/1"'), false));

  process.stdout.write(`${JSON.stringify({ protocol: "aml-capsule-cross-runtime-check/1", passed: true, results }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
