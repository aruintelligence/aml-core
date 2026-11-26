// Directive 010 closure: Python evidence verifiers and /v1/deployment/batch.
// `verified` / `effective_allowed` are never permission.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createAmlHttpServer } from "../server/httpServer.js";
import { executeAccountableIntent } from "../compiler/accountablePipeline.js";
import { createEvidenceCapsule } from "../runtime/evidenceCapsule.js";

const NOT_AUTH = "NOT AN AUTHORIZATION DECISION";
const ZERO = "0".repeat(64);
const py = args => {
  const out = spawnSync("python3", args, { encoding: "utf8", env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" } });
  return { status: out.status, json: JSON.parse(out.stdout || "null"), stderr: out.stderr };
};
const pinOf = file => spawnSync("python3", ["independent/python/authorization_cli.py", "policy-sha256", file], { encoding: "utf8" }).stdout.trim();
function tmp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-d010-closure-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("Python archive verifier: verified is not authorized without the relying-party policy pin", t => {
  const dir = tmp(t);
  const archive = "independent/vectors/archive-v1/archive.json";
  const policyFile = "independent/vectors/archive-v1/trusted-policy.json";
  const pin = pinOf(policyFile);
  assert.match(pin, /^[0-9a-f]{64}$/);
  const v = "independent/python/verify_evidence_archive.py";
  const unpinned = py([v, archive, policyFile]);
  assert.equal(unpinned.status, 3);
  assert.equal(unpinned.json.verified, true);
  assert.equal(unpinned.json.authorized, false);
  assert.equal(unpinned.json.decision_use, NOT_AUTH);
  assert.deepEqual(unpinned.json.authorization.reasons, ["AML_AUTHZ_POLICY_NOT_PINNED"]);
  const pinned = py([v, archive, policyFile, "--expected-policy-sha256", pin]);
  assert.equal(pinned.status, 0, pinned.stderr);
  assert.equal(pinned.json.authorized, true);
  assert.deepEqual(pinned.json.authorization.reasons, ["AML_AUTHZ_ALLOW"]);
  assert.equal(py([v, archive, policyFile, "--expected-policy-sha256", ZERO]).status, 3);
  assert.equal(py([v, archive, policyFile, "--expected-policy-sha256", pin.toUpperCase()]).status, 3, "non-canonical pin");
  const diagnostic = py([v, archive, policyFile, "--diagnostic-only"]);
  assert.equal(diagnostic.status, 0);
  assert.equal(diagnostic.json.authorized, false);
  assert.equal(diagnostic.json.decision_use, NOT_AUTH);
  // Exploit (c8a2316 exit 0): a substituted policy file that also trusts an
  // attacker key still verifies the genuine archive; the pin rejects it.
  const policy = JSON.parse(fs.readFileSync(policyFile, "utf8"));
  const widened = path.join(dir, "widened.json");
  fs.writeFileSync(widened, JSON.stringify({ ...policy, trusted_fingerprints: [...policy.trusted_fingerprints, "e".repeat(64)] }));
  const substituted = py([v, archive, widened, "--expected-policy-sha256", pin]);
  assert.equal(substituted.status, 3);
  assert.equal(substituted.json.verified, true);
  assert.equal(py([v, archive, widened]).status, 3);
  // A pin never rescues failed verification; a flag without a value is a usage error.
  assert.equal(py([v, archive, policyFile, "--expected-policy-sha256"]).status, 1);
});

test("Python migration recover writes nothing without the full authorization decision", t => {
  const dir = tmp(t);
  const v = "independent/python/verify_evidence_migration.py";
  const handoff = "independent/vectors/migration-v1/migration.json";
  const policyFile = "independent/vectors/archive-v1/trusted-policy.json";
  for (const extra of [[], ["--diagnostic-only"], ["--expected-policy-sha256", ZERO]]) {
    const target = path.join(dir, `r-${extra.length}-${extra[1] ?? ""}.json`);
    const out = py([v, "recover", handoff, policyFile, target, ...extra]);
    assert.equal(out.status, 1, extra.join(" "));
    assert.equal(out.json.reason, "recover_requires_authorization");
    assert.equal(fs.existsSync(target), false);
  }
  const target = path.join(dir, "authorized.json");
  const ok = py([v, "recover", handoff, policyFile, target, "--expected-policy-sha256", pinOf(policyFile)]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.json.authorized, true);
  assert.equal(fs.existsSync(target), true);
});

test("Python capsule verifier: an unsigned capsule without a pinned trust policy is never authorized", t => {
  const v = "independent/python/verify_evidence_capsule.py";
  const dir = tmp(t);
  // Exploit (c8a2316 exit 0): anyone can produce an unsigned, internally consistent capsule.
  const capsule = createEvidenceCapsule(executeAccountableIntent(allowed, { timestamp: "2030-01-01T00:00:00.000Z" }));
  const file = path.join(dir, "capsule.json");
  fs.writeFileSync(file, JSON.stringify(capsule));
  const out = py([v, file]);
  assert.equal(out.status, 3, out.stderr);
  assert.equal(out.json.verified, true);
  assert.equal(out.json.authorized, false);
  assert.deepEqual(out.json.authorization.reasons, ["AML_AUTHZ_POLICY_NOT_PINNED"]);
  assert.equal(py([v, file, "--expected-policy-sha256", ZERO]).status, 3, "a pin without a policy file cannot match");
  assert.equal(py([v, file, "--diagnostic-only"]).status, 0);
  const bad = path.join(dir, "bad.json");
  fs.writeFileSync(bad, "{}");
  assert.equal(py([v, bad]).status, 1);
});

async function withServer(options, fn) {
  const server = createAmlHttpServer({ default_profile: "human_first", ...options });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try { await fn(`http://127.0.0.1:${server.address().port}`); }
  finally { server.close(); await once(server, "close"); }
}
const allowed = { transmission: "ok", nodes: [{ type: "message", identifier: "Greeting", properties: {
  purpose: "Explain the test clearly.", attention_cost: 1, restoration_value: 3, collects_personal_data: false, consent_required: false } }] };
const pressure = { transmission: "p", nodes: [{ type: "message", identifier: "Pressure", properties: {
  purpose: "Create urgency", attention_cost: 5, restoration_value: 1 } }] };
const batch = (base, body) => fetch(`${base}/v1/deployment/batch`, { method: "POST",
  headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then(async r => ({ status: r.status, body: await r.json() }));

test("/v1/deployment/batch: request-chosen shadow mode is never permission", async () => {
  await withServer({}, async base => {
    const r = await batch(base, { intents: [pressure, allowed], mode: "shadow" });
    assert.equal(r.status, 200);
    assert.equal(r.body.results[0].effective_allowed, true, "shadow mode lets the suppressed intent through");
    assert.equal(r.body.results[0].aml_allowed, false);
    assert.equal(r.body.results[0].authorized, false);
    assert.ok(r.body.results[0].authorization.reasons.includes("AML_AUTHZ_POLICY_DENIED"));
    // Even an AML-allowed item is not authorized under a request-chosen policy.
    assert.equal(r.body.results[1].authorized, false);
    assert.deepEqual(r.body.results[1].authorization.reasons, ["AML_AUTHZ_POLICY_CHOSEN_BY_REQUEST"]);
    assert.equal(r.body.authorized, false);
    assert.equal(r.body.authorized_count, 0);
    assert.equal(r.body.decision_use, NOT_AUTH);
  });
});

test("/v1/deployment/batch: authorized only when non-empty and every item is allowed under a server-locked policy", async () => {
  await withServer({ locked_policy: { profile: "human_first", context: {} } }, async base => {
    const ok = await batch(base, { intents: [allowed, allowed] });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.authorized, true);
    assert.equal(ok.body.authorized_count, 2);
    for (const item of ok.body.results) {
      assert.equal(item.authorized, true);
      assert.deepEqual(item.authorization.reasons, ["AML_AUTHZ_ALLOW"]);
    }
    const mixed = await batch(base, { intents: [allowed, pressure] });
    assert.equal(mixed.body.authorized, false);
    assert.equal(mixed.body.results[0].authorized, true);
    assert.equal(mixed.body.results[1].authorized, false);
    assert.equal(mixed.body.authorized_count, 1);
    const empty = await batch(base, { intents: [] });
    assert.equal(empty.status, 200);
    assert.equal(empty.body.authorized, false, "an empty batch authorizes nothing");
  });
});

test("CI bundle step makes a genuine pinned decision (no diagnostic mode, no ignored exit 3)", t => {
  const ci = fs.readFileSync(".github/workflows/ci.yml", "utf8");
  const step = ci.slice(ci.indexOf("- name: Verify compiled bundle integrity"), ci.indexOf("- name: Reject unpinned"));
  assert.match(step, /AML_MANIFEST_SHA256: \$\{\{ steps\.compile\.outputs\.manifest_sha256 \}\}/);
  assert.match(step, /run: node bin\/aml\.js verify "\$\{RUNNER_TEMP\}\/aml-dist\/build_manifest\.json" --expected-sha256 "\$AML_MANIFEST_SHA256"\n/);
  assert.doesNotMatch(step, /--diagnostic-only|\|\| true|continue-on-error|exit 3|set \+e/);
  assert.match(ci, /echo "manifest_sha256=\$\{manifest_sha256\}" >> "\$GITHUB_OUTPUT"/);
  assert.match(ci, /run: node scripts\/check-ci-bundle-pin\.mjs "\$\{RUNNER_TEMP\}\/aml-dist" "\$AML_MANIFEST_SHA256"/);
  const dir = tmp(t);
  const dist = path.join(dir, "aml-dist");
  const compiled = spawnSync(process.execPath, ["bin/aml.js", "compile", "examples/transmission-061.aml", dist], { encoding: "utf8" });
  assert.equal(compiled.status, 0, compiled.stderr);
  const pin = createHash("sha256").update(fs.readFileSync(path.join(dist, "build_manifest.json"))).digest("hex");
  const verified = spawnSync(process.execPath, ["bin/aml.js", "verify", path.join(dist, "build_manifest.json"), "--expected-sha256", pin], { encoding: "utf8" });
  assert.equal(verified.status, 0, verified.stdout);
  assert.match(verified.stdout, /^Authorized: true$/m);
  const negative = spawnSync(process.execPath, ["scripts/check-ci-bundle-pin.mjs", dist, pin], { encoding: "utf8" });
  assert.equal(negative.status, 0, negative.stdout + negative.stderr);
  assert.deepEqual(JSON.parse(negative.stdout).failures, []);
  // the negative-control script itself fails closed on a wrong pin
  const wrong = spawnSync(process.execPath, ["scripts/check-ci-bundle-pin.mjs", dist, "0".repeat(64)], { encoding: "utf8" });
  assert.equal(wrong.status, 1);
});
