// Policy threshold rule (protocol/policyThreshold.js): an explicit threshold
// that is not a positive integer is a policy error, never silently 1. Covers
// governance policy-transition authorization (previously coerced to 1) and
// JS / Python / Go parity on shared vectors. Synthetic canary keys only.
import test, { after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { resolvePolicyThreshold } from "../protocol/policyThreshold.js";
import {
  createGovernancePolicyTransition, signGovernancePolicyTransition, createGovernancePolicyTransitionAuthorization,
  verifyGovernancePolicyTransitionAuthorization
} from "../protocol/governancePolicyAuthorization.js";
import {
  createGovernanceStreamSession, AML_GOVERNANCE_STREAM_OPEN, AML_GOVERNANCE_STREAM_POLICY_UPDATE
} from "../protocol/governanceStream.js";

const VECTORS = "conformance/policy-threshold/vectors.json";
const hasGo = spawnSync("go", ["version"]).status === 0;
let goDir = null;
after(() => { if (goDir) fs.rmSync(goDir, { recursive: true, force: true }); });

const key = () => crypto.generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
function authorization(nKeys, transmission = "canary-stream", epoch = 0, previous = "0".repeat(64)) {
  const transition = createGovernancePolicyTransition({ transmission, expected_policy_epoch: epoch,
    previous_policy_sha256: previous, update: { mode: "shadow" } });
  const sigs = Array.from({ length: nKeys }, (_, i) => signGovernancePolicyTransition(transition, key(), { signer: `canary-${i}` }));
  return { auth: createGovernancePolicyTransitionAuthorization(transition, sigs), fps: sigs.map(s => s.public_key_fingerprint_sha256) };
}

test("policy transition: an explicit invalid threshold fails closed instead of becoming 1", () => {
  const { auth, fps } = authorization(1);
  // Baseline control: one trusted signature meets threshold 1.
  assert.equal(verifyGovernancePolicyTransitionAuthorization(auth, { threshold: 1, trusted_fingerprints: fps }).authorized, true);
  for (const threshold of [0, -1, 1.5, "2", "", true, false, null, [2], { k: 2 }, Number.MAX_SAFE_INTEGER + 1, Infinity, NaN]) {
    const r = verifyGovernancePolicyTransitionAuthorization(auth, { threshold, trusted_fingerprints: fps });
    assert.equal(r.authorized, false, `threshold ${String(threshold)}`);
    assert.equal(r.valid, false);
    assert.equal(r.threshold, null);
    assert.deepEqual(r.policy_errors, ["invalid_threshold"]);
    assert.ok(r.errors.includes("invalid policy threshold: must be a positive integer"), r.errors.join(";"));
  }
});

test("policy transition: omitted threshold keeps the default 1; valid thresholds are enforced as written", () => {
  const { auth, fps } = authorization(2);
  const omitted = verifyGovernancePolicyTransitionAuthorization(auth, { trusted_fingerprints: fps });
  assert.equal(omitted.threshold, 1);
  assert.deepEqual(omitted.policy_errors, []);
  assert.equal(omitted.authorized, true);
  assert.equal(verifyGovernancePolicyTransitionAuthorization(auth, { threshold: 2, trusted_fingerprints: fps }).authorized, true);
  const three = verifyGovernancePolicyTransitionAuthorization(auth, { threshold: 3, trusted_fingerprints: fps });
  assert.equal(three.authorized, false);
  assert.deepEqual(three.policy_errors, []);
  assert.ok(three.errors.includes("eligible signature threshold not met: 2/3"));
});

test("governance stream: a session configured with an invalid threshold refuses the policy update", () => {
  const probe = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "canary-stream" });
  const { auth, fps } = authorization(1, probe.transmission, probe.policy_epoch, probe.policy_sha256);
  for (const threshold of ["1", 0]) {
    const session = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "canary-stream",
      policy_authorization: { required: true, threshold, trusted_fingerprints: fps } });
    assert.throws(() => session.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, mode: "shadow", authorization: auth }),
      /AML_POLICY_TRANSITION_UNAUTHORIZED:.*invalid policy threshold/);
    assert.equal(session.mode, "enforce");
    assert.equal(session.policy_epoch, 0);
  }
  const ok = createGovernanceStreamSession({ protocol: AML_GOVERNANCE_STREAM_OPEN, transmission: "canary-stream",
    policy_authorization: { required: true, threshold: 1, trusted_fingerprints: fps } });
  assert.equal(ok.accept({ protocol: AML_GOVERNANCE_STREAM_POLICY_UPDATE, mode: "shadow", authorization: auth }).authorization.authorized, true);
});

test("policy-threshold vectors are current and JavaScript, Python and Go agree", { timeout: 120_000 }, t => {
  const check = spawnSync(process.execPath, ["conformance/policy-threshold/generate.mjs", "--check"], { encoding: "utf8" });
  assert.equal(check.status, 0, check.stderr);
  const vectors = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
  const js = vectors.cases.map(c => ({ name: c.name, result: resolvePolicyThreshold(JSON.parse(c.policy_json)) }));
  vectors.cases.forEach((c, i) => assert.deepEqual(js[i].result, c.expect, c.name));
  assert.ok(vectors.cases.filter(c => c.expect.error === "invalid_threshold").length >= 10);
  const py = spawnSync("python3", ["independent/python/policy_threshold.py", "conformance", VECTORS], { encoding: "utf8", env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" } });
  assert.equal(py.status, 0, py.stderr);
  assert.deepEqual(JSON.parse(py.stdout).results, js, "python equals javascript");
  if (!hasGo) { t.diagnostic("go toolchain not installed: Go policy-threshold conformance skipped"); return; }
  goDir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-go-pt-"));
  const bin = path.join(goDir, "aml-go-witness");
  const built = spawnSync("go", ["build", "-o", bin, "."], { cwd: "independent/go", encoding: "utf8" });
  assert.equal(built.status, 0, built.stderr);
  const g = spawnSync(bin, ["policy-threshold-conformance", VECTORS], { encoding: "utf8" });
  assert.equal(g.status, 0, g.stderr);
  assert.deepEqual(JSON.parse(g.stdout).results, js, "go equals javascript");
});
