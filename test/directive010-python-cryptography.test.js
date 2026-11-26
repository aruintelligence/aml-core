// Directive 010: cryptography is required only for Ed25519 checks. Missing
// crypto must never authorize, and policy-sha256 must still work without it.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";
import { executeAccountableIntent } from "../compiler/accountablePipeline.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const POLICY = "independent/vectors/archive-v1/trusted-policy.json";
const NOT_AUTH = "NOT AN AUTHORIZATION DECISION";
const allowed = { transmission: "ok", nodes: [{ type: "message", identifier: "Greeting", properties: {
  purpose: "Explain the test clearly.", attention_cost: 1, restoration_value: 3, collects_personal_data: false, consent_required: false } }] };

function tmp(t, prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function python(args, extraEnv = {}, exe = "python3") {
  const out = spawnSync(exe, args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1", PYTHONNOUSERSITE: "1", ...extraEnv },
  });
  let json = null;
  try { json = JSON.parse(out.stdout || "null"); } catch { json = null; }
  return { status: out.status, json, stdout: out.stdout, stderr: out.stderr };
}

// PYTHONPATH blocker: a dummy `cryptography` package wins over site-packages.
function blockedEnv(t) {
  const dir = tmp(t, "aml-block-crypto-");
  fs.writeFileSync(path.join(dir, "sitecustomize.py"),
    "import sys\n" +
    "for name in list(sys.modules):\n" +
    "    if name == 'cryptography' or name.startswith('cryptography.'):\n" +
    "        del sys.modules[name]\n");
  fs.mkdirSync(path.join(dir, "cryptography"));
  fs.writeFileSync(path.join(dir, "cryptography", "__init__.py"),
    "raise ModuleNotFoundError('cryptography blocked for test')\n");
  const pythonpath = dir + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : "");
  return { PYTHONPATH: pythonpath, PYTHONNOUSERSITE: "1", PYTHONDONTWRITEBYTECODE: "1" };
}

function writeUnsignedCapsule(dir) {
  const capsule = createEvidenceCapsule(executeAccountableIntent(allowed, { timestamp: "2030-01-01T00:00:00.000Z" }));
  const file = path.join(dir, "capsule.json");
  fs.writeFileSync(file, JSON.stringify(capsule));
  return file;
}

function writeSignedCapsule(dir) {
  const capsule = createEvidenceCapsule(executeAccountableIntent(allowed, { timestamp: "2030-01-01T00:00:00.000Z" }));
  capsule.receipt.signature = {
    protocol: "ĀML Execution Receipt Attestation",
    version: "1.1",
    algorithm: "Ed25519",
    signer: "test",
    signed_at: "2030-01-01T00:00:00Z",
    public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA" + "A".repeat(44) + "\n-----END PUBLIC KEY-----\n",
    public_key_sha256: "0".repeat(64),
    signature_base64: Buffer.alloc(64).toString("base64"),
  };
  const file = path.join(dir, "signed-capsule.json");
  fs.writeFileSync(file, JSON.stringify(capsule));
  // Recompute capsule digests after adding the signature (receipt_sha256
  // excludes the signature field, but the capsule digest covers the receipt).
  const hashed = python(["-c",
    "import hashlib, json, pathlib, sys; sys.path.insert(0, 'independent/python'); " +
    "from verify_evidence_capsule import canonical; " +
    "cap = json.loads(pathlib.Path(sys.argv[1]).read_text()); " +
    "payload = {k: v for k, v in cap.items() if k != 'digests'}; " +
    "data = canonical(payload); " +
    "cap['digests'] = {'sha256': hashlib.sha256(data).hexdigest(), 'sha512': hashlib.sha512(data).hexdigest()}; " +
    "pathlib.Path(sys.argv[1]).write_text(json.dumps(cap))", file]);
  if (hashed.status !== 0) throw new Error(hashed.stderr || hashed.stdout);
  const policy = path.join(dir, "receipt-policy.json");
  fs.writeFileSync(policy, JSON.stringify({ trusted_receipt_fingerprints: ["0".repeat(64)] }));
  return { file, policy };
}

test("policy-sha256 and an unsigned capsule work when cryptography is blocked from sys.modules", t => {
  const env = blockedEnv(t);
  const dir = tmp(t, "aml-unsigned-");
  const pin = python(["independent/python/authorization_cli.py", "policy-sha256", POLICY], env);
  assert.equal(pin.status, 0, pin.stderr);
  assert.match(pin.stdout.trim(), /^[0-9a-f]{64}$/);
  const file = writeUnsignedCapsule(dir);
  const out = python(["independent/python/verify_evidence_capsule.py", file], env);
  assert.equal(out.status, 3, out.stderr);
  assert.equal(out.json.verified, true);
  assert.equal(out.json.authorized, false);
  assert.equal(out.json.decision_use, NOT_AUTH);
  assert.deepEqual(out.json.authorization.reasons, ["AML_AUTHZ_POLICY_NOT_PINNED"]);
});

test("capsule verifier without cryptography fails closed on a signature path: non-zero, not authorized, clear error", t => {
  const env = blockedEnv(t);
  const dir = tmp(t, "aml-signed-");
  const { file, policy } = writeSignedCapsule(dir);
  const out = python(["independent/python/verify_evidence_capsule.py", file, policy], env);
  assert.notEqual(out.status, 0, out.stderr + out.stdout);
  assert.ok(out.status === 1 || out.status === 3, `expected non-zero denial, got ${out.status}`);
  assert.ok(out.json, out.stdout);
  assert.equal(out.json.verified, false);
  assert.equal(out.json.authorized, false);
  assert.equal(out.json.decision_use, NOT_AUTH);
  assert.match(String(out.json.reason), /cryptography/i);
  assert.ok(!out.json.authorization?.reasons?.includes("AML_AUTHZ_ALLOW"));
  const diagnostic = python(["independent/python/verify_evidence_capsule.py", file, policy, "--diagnostic-only"], env);
  assert.notEqual(diagnostic.status, 0, "diagnostic-only must not exit 0 when verification could not run");
  assert.equal(diagnostic.json?.authorized, false);
  assert.equal(diagnostic.json?.verified, false);
});

function resolvePython312() {
  for (const exe of [process.env.AML_PYTHON312, "python3.12", "python3"].filter(Boolean)) {
    const r = spawnSync(exe, ["-c", "import sys; print(sys.version)"], { encoding: "utf8" });
    if (r.status === 0 && /^3\.12\./.test(r.stdout.trim())) return exe;
  }
  return null;
}

test("the three Pilot 003 Python closure tests pass in a clean 3.12 venv with cryptography installed", t => {
  const exe = resolvePython312();
  if (!exe) {
    t.skip("Python 3.12 is not available to mimic actions/setup-python");
    return;
  }
  const dir = tmp(t, "aml-pilot003-venv-");
  const venv = path.join(dir, "venv");
  const created = spawnSync(exe, ["-m", "venv", "--clear", venv], { encoding: "utf8" });
  assert.equal(created.status, 0, created.stderr);
  const venvPython = path.join(venv, "bin", "python");
  // Prove isolation: the venv must not see the host's cryptography until we install it.
  const isolated = spawnSync(venvPython, ["-c", "import cryptography"], { encoding: "utf8" });
  assert.notEqual(isolated.status, 0, "venv unexpectedly inherited a system cryptography package");
  const pip = spawnSync(venvPython, ["-m", "pip", "install", "--disable-pip-version-check", "cryptography>=42,<51"], {
    encoding: "utf8",
    timeout: 180_000,
  });
  assert.equal(pip.status, 0, pip.stdout + pip.stderr);
  const present = spawnSync(venvPython, ["-c", "import cryptography; print(cryptography.__version__)"], { encoding: "utf8" });
  assert.equal(present.status, 0, present.stderr);
  const pattern = "Python archive verifier|Python migration recover|Python capsule verifier";
  const run = spawnSync(process.execPath, ["--test", "--test-reporter=tap", "--test-name-pattern", pattern, "test/directive010-closure.test.js"], {
    cwd: root,
    encoding: "utf8",
    timeout: 120_000,
    env: Object.fromEntries(Object.entries({
      ...process.env,
      PATH: path.join(venv, "bin") + path.delimiter + process.env.PATH,
      PYTHONDONTWRITEBYTECODE: "1",
      PYTHONNOUSERSITE: "1",
    }).filter(([key]) => !key.startsWith("NODE_TEST"))),
  });
  const output = `${run.stdout}\n${run.stderr}`;
  assert.equal(run.status, 0, output);
  // Node 20 still lists skipped file-mates in the TAP summary (`# tests 6`,
  // `# skipped 3`); Node 24 reports only the three matches (`# tests 3`).
  assert.match(output, /# pass 3/);
  assert.match(output, /# fail 0/);
});
