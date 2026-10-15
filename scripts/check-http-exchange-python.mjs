// Cross-runtime challenge of saved responses from the real locked HTTP service.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { signExecutionReceipt } from "../compiler/accountablePipeline.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aml-locked-http-python-"));
const captureDir = path.join(directory, "capture");
const verifier = path.resolve("independent/python/verify_http_exchange.py");
const pythonEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
const read = name => JSON.parse(fs.readFileSync(path.join(captureDir, name), "utf8"));
const save = (name, value) => {
  const file = path.join(directory, name);
  fs.writeFileSync(file, typeof value === "string" ? value : JSON.stringify(value));
  return file;
};
const rehash = capsule => {
  const { digests, ...payload } = capsule;
  const bytes = canonicalJSONStringify(payload);
  capsule.digests = Object.fromEntries(["sha256", "sha512"].map(algorithm =>
    [algorithm, createHash(algorithm).update(bytes).digest("hex")]));
};

try {
  const capture = spawnSync(process.execPath,
    ["pilots/enterprise-http-gate/capture.mjs", "--out", captureDir], { encoding: "utf8" });
  assert.equal(capture.status, 0, capture.stderr);
  const captured = JSON.parse(capture.stdout);
  assert.equal(captured.cases.length, 3);
  const original = Object.fromEntries(["allow", "suppress", "numeric"].map(name => [name, {
    exchange: read(`exchange-${name}.json`), capsule: read(`capsule-${name}.json`),
    expected: read(`host-expected-${name}.json`)
  }]));
  const pinned = read("trusted-policy.json");
  const results = [];
  function check(name, base, status, reason, mutate = () => {}) {
    const sample = structuredClone(original[base]);
    const policy = structuredClone(pinned);
    mutate(sample, policy);
    const inputs = [sample.exchange, sample.capsule, sample.expected, policy]
      .map((value, index) => save(`${name}-${index}.json`, value));
    const result = spawnSync("python3", [verifier, ...inputs], { encoding: "utf8", env: pythonEnv });
    if (result.error) throw result.error;
    const report = JSON.parse(result.stdout);
    assert.equal(result.status, status === "blocked" ? 1 : 0, `${name}: ${result.stderr} ${result.stdout}`);
    assert.equal(report.status, status, name);
    assert.equal(report.reason, reason, name);
    assert.equal(report.verified, status !== "blocked", name);
    assert.equal(report.render_eligible, status === "allow", name);
    if (status !== "blocked") {
      assert.equal(report.receipt_sha256, sample.exchange.body.receipt.receipt_sha256, name);
      assert.equal(report.output_sha256, sample.exchange.body.receipt.output_sha256, name);
    }
    results.push({ id: name, status: report.status, reason: report.reason });
    return report;
  }
  const allowed = check("valid_allow", "allow", "allow", "verified_allow");
  check("valid_suppression", "suppress", "suppressed", "policy_suppressed");
  check("valid_numeric_exponent", "numeric", "allow", "verified_allow");
  check("numeric_host_expectation_changed", "numeric", "blocked", "receipt_binding_mismatch", sample => {
    sample.expected.intent.numeric_probe = 2e-7;
  });
  const swapped = check("outer_html_swap", "allow", "allow", "verified_allow", sample => {
    sample.exchange.body.selected_render.html = "<h2>Unreviewed replacement</h2>";
  });
  assert.equal(swapped.output_sha256, allowed.output_sha256);
  assert.notEqual(createHash("sha256").update("<h2>Unreviewed replacement</h2>").digest("hex"), swapped.output_sha256);
  check("http_failure", "allow", "blocked", "invalid_http_exchange", sample => { sample.exchange.http_status = 503; });
  check("request_selected_policy", "allow", "blocked", "unexpected_deployment_policy", sample => { sample.exchange.body.policy_source = "request_or_default"; });
  check("shadow_mode", "allow", "blocked", "unexpected_deployment_policy", sample => { sample.exchange.body.mode = "shadow"; });
  check("open_failure_mode", "allow", "blocked", "unexpected_deployment_policy", sample => { sample.exchange.body.failure_mode = "open"; });
  check("evaluation_error", "allow", "blocked", "unexpected_deployment_policy", sample => { sample.exchange.body.evaluation_error = "failed"; });
  check("flipped_decision", "allow", "blocked", "decision_mismatch", sample => { sample.exchange.body.effective_allowed = false; });
  check("profile_substitution", "allow", "blocked", "receipt_binding_mismatch", sample => { sample.expected.profile = "calm_default"; });
  check("consent_context_substitution", "suppress", "blocked", "receipt_binding_mismatch", sample => { sample.expected.context.consent_granted = true; });
  check("intent_substitution", "allow", "blocked", "receipt_binding_mismatch", sample => { sample.expected.intent.transmission = "other"; });
  check("replayed_nonce", "allow", "blocked", "receipt_binding_mismatch", sample => { sample.expected.request_nonce = "a".repeat(64); });
  check("unsigned_receipt", "allow", "blocked", "unsigned_or_unsupported_receipt", sample => { delete sample.exchange.body.receipt.signature; });
  check("foreign_signer", "allow", "blocked", "invalid_capsule_or_trust", sample => {
    const { signature, ...unsigned } = sample.exchange.body.receipt;
    const foreign = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
    const receipt = signExecutionReceipt(unsigned, foreign, { signer: "foreign-fixture" });
    sample.exchange.body.receipt = receipt;
    sample.capsule = createEvidenceCapsule(receipt);
  });
  check("receipt_content_changed", "allow", "blocked", "invalid_capsule_or_trust", sample => {
    sample.exchange.body.receipt.selected_render.html = "<h2>Altered</h2>";
    sample.capsule.receipt.selected_render.html = "<h2>Altered</h2>";
    rehash(sample.capsule);
  });
  check("signature_attribution_changed", "allow", "blocked", "invalid_capsule_or_trust", sample => {
    sample.exchange.body.receipt.signature.signer = "impostor";
    sample.capsule.receipt.signature.signer = "impostor";
    rehash(sample.capsule);
  });
  check("capsule_digest_changed", "allow", "blocked", "invalid_capsule_or_trust", sample => { sample.capsule.digests.sha256 = "0".repeat(64); });
  check("capsule_not_response", "allow", "blocked", "capsule_response_mismatch", sample => { sample.exchange.body.receipt.timestamp = "2030-01-01T00:00:00Z"; });
  check("wrong_trust_pin", "allow", "blocked", "invalid_capsule_or_trust", (_, policy) => { policy.trusted_receipt_fingerprints = ["f".repeat(64)]; });
  check("revoked_trust_pin", "allow", "blocked", "invalid_capsule_or_trust", (_, policy) => { policy.revoked_receipt_fingerprints = [...policy.trusted_receipt_fingerprints]; });

  // Reject ambiguity in hostile source JSON before the Python verifier sees it.
  const duplicate = JSON.stringify(original.allow.exchange).replace(
    '"protocol":"aml-locked-http-exchange/1"',
    '"protocol":"aml-locked-http-exchange/1","protocol":"aml-locked-http-exchange/1"');
  assert.notEqual(duplicate, JSON.stringify(original.allow.exchange));
  const files = [save("duplicate.json", duplicate),
    path.join(captureDir, "capsule-allow.json"), path.join(captureDir, "host-expected-allow.json"),
    path.join(captureDir, "trusted-policy.json")];
  const parsed = spawnSync("python3", [verifier, ...files], { encoding: "utf8", env: pythonEnv });
  assert.equal(parsed.status, 1, parsed.stderr);
  assert.equal(JSON.parse(parsed.stdout).reason, "invalid_input");
  results.push({ id: "duplicate_json_key", status: "blocked", reason: "invalid_input" });

  process.stdout.write(`${JSON.stringify({ protocol: "aml-locked-http-python-cross-runtime/1",
    passed: true, case_count: results.length, cases: results,
    claim_boundary: "Project-authored localhost fixtures, separate Python verification of saved JSON; no external witness, network identity, or browser render proof." }, null, 2)}\n`);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
