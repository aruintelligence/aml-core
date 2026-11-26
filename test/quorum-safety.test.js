// k-of-n witness quorum safety (protocol/quorumSafety.js): a configuration is
// accepted only when 2k - n - 1 >= 1, identically in JS, Python and Go, and a
// pinned governance-witness policy with an unsafe k-of-n never authorizes.
// Synthetic canary keys only.
import test, { after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { evaluateQuorumSafety } from "../protocol/quorumSafety.js";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import { signGovernanceStreamTranscript } from "../protocol/governanceTranscriptSignature.js";
import { evaluateGovernanceWitnessQuorum, verifyGovernanceWitnessQuorum } from "../protocol/governanceWitnessQuorum.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const VECTORS = "conformance/quorum-safety/vectors.json";
const hasGo = spawnSync("go", ["version"]).status === 0;
let goDir = null;
after(() => { if (goDir) fs.rmSync(goDir, { recursive: true, force: true }); });

test("rule: exact accepted set for n <= 8, and the named unsafe configurations", () => {
  const accepted = [];
  for (let n = 1; n <= 8; n += 1) for (let k = 1; k <= n; k += 1) if (evaluateQuorumSafety(k, n).valid) accepted.push(`${k}-of-${n}`);
  assert.deepEqual(accepted, ["2-of-2", "3-of-3", "3-of-4", "4-of-4", "4-of-5", "5-of-5", "4-of-6", "5-of-6", "6-of-6",
    "5-of-7", "6-of-7", "7-of-7", "5-of-8", "6-of-8", "7-of-8", "8-of-8"]);
  const reason = (k, n) => evaluateQuorumSafety(k, n).reason;
  assert.equal(reason(4, 7), "zero_fault_tolerance");
  assert.equal(reason(2, 3), "zero_fault_tolerance");
  assert.equal(reason(1, 1), "zero_fault_tolerance");
  assert.equal(reason(2, 4), "quorums_may_not_intersect");
  assert.equal(reason(1, 2), "quorums_may_not_intersect");
  assert.deepEqual(evaluateQuorumSafety(3, 4), { valid: true, reason: null, threshold: 3, witness_count: 4,
    quorum_intersection: 2, safety_fault_tolerance: 1, liveness_fault_tolerance: 1 });
  assert.equal(evaluateQuorumSafety(5, 7).safety_fault_tolerance, 2);
  // n-of-n passes the safety rule but tolerates no unavailable witness.
  assert.equal(evaluateQuorumSafety(3, 3).liveness_fault_tolerance, 0);
});

test("vectors are current and JavaScript, Python and Go agree on all of them", { timeout: 120_000 }, t => {
  const check = spawnSync(process.execPath, ["conformance/quorum-safety/generate.mjs", "--check"], { encoding: "utf8" });
  assert.equal(check.status, 0, check.stderr);
  const vectors = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
  const js = vectors.cases.map(c => {
    const got = evaluateQuorumSafety(c.threshold, c.witness_count);
    return Object.fromEntries(Object.keys(c.expect).map(k => [k, got[k] ?? null]));
  });
  vectors.cases.forEach((c, i) => assert.deepEqual(js[i], c.expect, `js ${c.threshold}-of-${c.witness_count}`));
  const py = spawnSync("python3", ["independent/python/quorum_safety.py", "conformance", VECTORS], { encoding: "utf8", env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" } });
  assert.equal(py.status, 0, py.stderr);
  assert.deepEqual(JSON.parse(py.stdout).results, js, "python equals javascript");
  if (!hasGo) { t.diagnostic("go toolchain not installed: Go quorum-safety conformance skipped"); return; }
  goDir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-go-qs-"));
  const bin = path.join(goDir, "aml-go-witness");
  const built = spawnSync("go", ["build", "-o", bin, "."], { cwd: "independent/go", encoding: "utf8" });
  assert.equal(built.status, 0, built.stderr);
  const g = spawnSync(bin, ["quorum-safety-conformance", VECTORS], { encoding: "utf8" });
  assert.equal(g.status, 0, g.stderr);
  assert.deepEqual(JSON.parse(g.stdout).results, js, "go equals javascript");
});

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(JSON.parse);
const transcript = createGovernanceStreamTranscript(messages);
const witness = name => signGovernanceStreamTranscript(transcript,
  crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }), { signer: name, scope: "governance-witness" });
const fpOf = w => w.signature.public_key_fingerprint_sha256;
const policySha = p => crypto.createHash("sha256").update(canonicalJSONStringify(p)).digest("hex");

function runCli(t, policy, signed) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-qs-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "input.json");
  fs.writeFileSync(file, JSON.stringify({ policy, signed_transcripts: signed }));
  const out = spawnSync(process.execPath, ["bin/aml-governance-witness-quorum.js", file, "--expected-policy-sha256", policySha(policy)], { encoding: "utf8" });
  return { status: out.status, json: JSON.parse(out.stdout) };
}

test("aml-governance-witness-quorum: a pinned 2-of-3 or 4-of-7 policy is refused; 3-of-4 and 5-of-7 authorize", t => {
  const ws = Array.from({ length: 7 }, (_, i) => witness(`w${i}`));
  const policy = (k, n) => ({ threshold: k, trusted_fingerprints: ws.slice(0, n).map(fpOf), required_scope: "governance-witness" });
  for (const [k, n] of [[2, 3], [4, 7], [1, 1], [2, 4]]) {
    const r = runCli(t, policy(k, n), ws.slice(0, n));
    assert.equal(r.json.quorum_met, true, `${k}-of-${n} evidence meets the threshold`);
    assert.equal(r.status, 3, `${k}-of-${n} must not authorize`);
    assert.deepEqual(r.json.authorization.reasons, ["AML_AUTHZ_QUORUM_CONFIG_UNSAFE"], `${k}-of-${n}`);
    assert.equal(r.json.quorum_safety.valid, false);
  }
  for (const [k, n] of [[3, 4], [5, 7]]) {
    const r = runCli(t, policy(k, n), ws.slice(0, k));
    assert.equal(r.status, 0, `${k}-of-${n} positive control: ${JSON.stringify(r.json.authorization?.reasons)}`);
    assert.equal(r.json.quorum_safety.valid, true);
  }
});

test("governance witness quorum: an explicit invalid threshold fails closed instead of becoming 1", () => {
  const ws = [witness("a"), witness("b")];
  const trusted = ws.map(fpOf);
  for (const threshold of ["2", 0, -1, 1.5, null, true]) {
    const r = evaluateGovernanceWitnessQuorum(ws, { threshold, trusted_fingerprints: trusted });
    assert.equal(r.quorum_met, false, `threshold ${JSON.stringify(threshold)}`);
    assert.equal(r.threshold, null);
    assert.deepEqual(r.policy_errors, ["invalid_threshold"]);
    assert.equal(verifyGovernanceWitnessQuorum(r).valid, false);
  }
  // Omitted threshold keeps the documented default (1), reported as unsafe for n = 2.
  const d = evaluateGovernanceWitnessQuorum(ws, { trusted_fingerprints: trusted });
  assert.equal(d.threshold, 1);
  assert.equal(d.quorum_safety.reason, "quorums_may_not_intersect");
});
