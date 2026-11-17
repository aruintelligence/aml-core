// Trust-config parity: JS, Python and Go evaluate the same signed trust config
// identically (shared vectors), share durable state and the single-use store,
// and every verifier obeys the enrolled-host rule. Synthetic canary keys only.
import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { signTrustConfig, initTrustState } from "../runtime/trustConfig.js";
import { runVectors } from "../conformance/trust-config/run-js.mjs";
import { sealBrowserReceipt } from "../docs/aml-browser-integrity.js";
import { createBrowserEvidence } from "../docs/aml-browser-evidence.js";
import { createVerificationChallenge } from "../docs/aml-verification-challenge.js";
import { createSessionAttestation } from "../docs/aml-session-attestation.js";
import { createWitnessBundle } from "../docs/aml-witness-bundle.js";
import { canaryKey, configBody, tempDir } from "./fixtures/trust-config/helpers.mjs";

const VECTORS = "conformance/trust-config/vectors.json";
const hasGo = spawnSync("go", ["version"]).status === 0;
const NO_TRUST_ENV = Object.fromEntries(Object.entries(process.env).filter(([k]) => !["AML_TRUST_STATE_DIR", "AML_VERIFY_AT"].includes(k)));
const run = (binary, args, env = {}) => {
  const out = spawnSync(binary, args, { encoding: "utf8", env: { ...NO_TRUST_ENV, PYTHONDONTWRITEBYTECODE: "1", ...env }, maxBuffer: 1 << 26 });
  let json = null;
  try { json = JSON.parse(out.stdout); } catch { /* not JSON */ }
  return { status: out.status, json, stdout: out.stdout, stderr: out.stderr };
};
let goBinary = null;
let goDir = null;
after(() => { if (goDir) fs.rmSync(goDir, { recursive: true, force: true }); });
function go() {
  if (goBinary) return goBinary;
  const dir = goDir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-go-bin-"));
  const built = spawnSync("go", ["build", "-o", path.join(dir, "aml-go-witness"), "."], { cwd: "independent/go", encoding: "utf8" });
  assert.equal(built.status, 0, built.stderr);
  goBinary = path.join(dir, "aml-go-witness");
  return goBinary;
}

function compare(results, vectors, label) {
  const mismatches = [];
  vectors.cases.forEach((c, i) => c.steps.forEach((s, j) => {
    const got = results.results[i]?.steps[j];
    if (results.results[i]?.name !== c.name) mismatches.push(`${label}: case ${i} name`);
    for (const [k, v] of Object.entries(s.expect)) if (!isDeepStrictEqual(got?.[k], v)) mismatches.push(`${label}: ${c.name}[${j}].${k} = ${JSON.stringify(got?.[k])}, expected ${JSON.stringify(v)}`);
  }));
  return mismatches;
}

test("conformance vectors are current, include denial cases, and contain no private key", () => {
  const check = run(process.execPath, ["conformance/trust-config/generate.mjs", "--check"]);
  assert.equal(check.status, 0, check.stderr);
  const text = fs.readFileSync(VECTORS, "utf8");
  assert.doesNotMatch(text, /PRIVATE KEY/);
  const vectors = JSON.parse(text);
  const steps = vectors.cases.flatMap(c => c.steps);
  assert.ok(vectors.cases.length >= 40 && steps.filter(s => s.expect.trusted === false).length >= 30, "denials dominate");
});

test("JavaScript, Python and Go agree on every conformance step (including denials)", { timeout: 120_000 }, t => {
  const vectors = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
  const js = runVectors(vectors);
  assert.deepEqual(compare(js, vectors, "js"), []);
  const py = run("python3", ["independent/python/trust_config.py", "conformance", VECTORS]);
  assert.equal(py.status, 0, py.stderr);
  assert.deepEqual(compare(py.json, vectors, "python"), []);
  assert.deepEqual(py.json.results, JSON.parse(JSON.stringify(js.results)), "python full results equal javascript");
  if (!hasGo) { t.diagnostic("go toolchain not installed: Go conformance skipped"); return; }
  const g = run(go(), ["trust-conformance", VECTORS]);
  assert.equal(g.status, 0, g.stderr);
  assert.deepEqual(compare(g.json, vectors, "go"), []);
  assert.deepEqual(g.json.results, JSON.parse(JSON.stringify(js.results)), "go full results equal javascript");
});

function enrolled(t, overrides = {}) {
  const dir = tempDir(t, "aml-parity-");
  const roots = [canaryKey(), canaryKey(), canaryKey()];
  const state = path.join(dir, "state");
  initTrustState(state, { threshold: 2, rootKeyids: roots.map(r => r.sha256) });
  const write = (name, value) => { const f = path.join(dir, name); fs.writeFileSync(f, typeof value === "string" ? value : `${JSON.stringify(value)}\n`); return f; };
  const config = (over = {}) => signTrustConfig(configBody(roots, { ...overrides, ...over }), [roots[0].pem, roots[1].pem]);
  return { dir, state, write, config, store: path.join(dir, "store") };
}

test("trust-verify: the three implementations share one durable state (rollback refused across languages)", t => {
  const e = enrolled(t);
  const v1 = e.write("v1.json", e.config({ version: 1 }));
  const v2 = e.write("v2.json", e.config({ version: 2 }));
  const clis = [["node", [process.execPath, "bin/aml.js", "trust-verify"]], ["python", ["python3", "independent/python/trust_config.py", "trust-verify"]]];
  if (hasGo) clis.push(["go", [go(), "trust-verify"]]);
  const verify = ([, [bin, ...pre]], file, env = {}) => run(bin, [...pre, "--trust-config", file, "--trust-state", e.state], env);
  // Python accepts v1, Go accepts v2, then nobody accepts v1 again.
  assert.equal(verify(clis[1], v1).status, 0, "python v1");
  assert.equal(verify(clis.at(-1), v2).status, 0, `${clis.at(-1)[0]} v2`);
  for (const cli of clis) {
    const back = verify(cli, v1);
    assert.equal(back.status, 3, `${cli[0]} rollback: ${back.stdout}`);
    assert.equal(back.json.authorized, false);
    assert.ok(back.json.reasons.includes("not_rolled_back"), cli[0]);
    assert.equal(verify(cli, v2).status, 0, `${cli[0]} current`);
    // Any caller-supplied time denies, in every language.
    const caller = verify(cli, v2, { AML_VERIFY_AT: "2030-01-01T00:00:00Z" });
    assert.equal(caller.status, 3, `${cli[0]} caller time`);
    assert.ok(caller.json.reasons.includes("caller_time_absent"), cli[0]);
  }
});

const QUORUM = "independent/python/signed-quorum-vector.json";
const HELD = "independent/python/signed-quorum-held-policy-vector.json";
const quorumClis = [["node", [process.execPath, "bin/aml.js", "verify-signed-quorum", QUORUM, "--policy", HELD]],
  ["python", ["python3", "independent/python/verify_signed_quorum.py", QUORUM, "--policy", HELD]]];
const reasonsOf = r => r.json?.authorization?.reasons ?? [];

test("signed quorum (JS and Python): enrolled host needs a trusted config; single use is shared across languages", t => {
  const e = enrolled(t);
  const good = e.write("good.json", e.config());
  for (const [label, [bin, ...args]] of quorumClis) {
    assert.equal(run(bin, args).status, 0, `${label}: baseline authorized without trust mode`);
    const bare = run(bin, args, { AML_TRUST_STATE_DIR: e.state });
    assert.equal(bare.status, 3, `${label}: enrolled host without --trust-config: ${bare.stdout.slice(0, 400)}`);
    assert.equal(bare.json.authorized, false, label);
    assert.ok(reasonsOf(bare).includes("AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED"), label);
    const unsigned = e.write(`one-sig-${label}.json`, { ...JSON.parse(fs.readFileSync(good, "utf8")), signatures: [] });
    assert.equal(run(bin, [...args, "--trust-config", unsigned, "--trust-state", e.state]).status, 3, `${label}: untrusted config`);
    assert.equal(run(bin, [...args, "--trust-config", good, "--trust-state", e.state]).status, 0, `${label}: trusted config`);
  }
  // Durable single use: whichever language consumes first, the other refuses.
  const first = run(quorumClis[1][1][0], [...quorumClis[1][1].slice(1), "--trust-config", good, "--trust-state", e.state, "--single-use-store", e.store]);
  assert.equal(first.status, 0, first.stdout.slice(0, 400));
  assert.equal(first.json.single_use.consumed, true);
  const second = run(quorumClis[0][1][0], [...quorumClis[0][1].slice(1), "--trust-config", good, "--trust-state", e.state, "--single-use-store", e.store]);
  assert.equal(second.status, 3, "node after python");
  assert.ok(reasonsOf(second).includes("AML_AUTHZ_ALREADY_CONSUMED"));
  const third = run(quorumClis[1][1][0], [...quorumClis[1][1].slice(1), "--single-use-store", e.store]);
  assert.equal(third.status, 3, "python again, explicit-pin mode");
  assert.ok(reasonsOf(third).includes("AML_AUTHZ_ALREADY_CONSUMED"));
});

test("signed quorum: a config requiring single use consumes in the enrolled store (no store or a fresh store cannot replay); diagnostic consumes nothing", t => {
  for (const [label, [bin, ...args]] of quorumClis) {
    const e = enrolled(t, { require_single_use: true });
    const cfg = e.write("su.json", e.config());
    const enrolledStore = path.join(e.state, "single-use", "consumed");
    const diag = run(bin, [...args, "--trust-config", cfg, "--trust-state", e.state, "--diagnostic-only"]);
    assert.equal(diag.json.authorized, false, label);
    assert.equal(fs.existsSync(enrolledStore) && fs.readdirSync(enrolledStore).length > 0, false, `${label}: diagnostic consumed`);
    const first = run(bin, [...args, "--trust-config", cfg, "--trust-state", e.state]);
    assert.equal(first.status, 0, `${label}: ${first.stdout.slice(0, 300)}`);
    assert.equal(fs.readdirSync(enrolledStore).length, 1, `${label}: consumed in the enrolled store`);
    for (const extra of [[], ["--single-use-store", path.join(e.dir, `fresh-${label}`)]]) {
      const replay = run(bin, [...args, "--trust-config", cfg, "--trust-state", e.state, ...extra]);
      assert.equal(replay.status, 3, `${label}: replay ${extra.join(" ")}`);
      assert.ok(reasonsOf(replay).includes("AML_AUTHZ_ALREADY_CONSUMED"), label);
    }
  }
});

test("witness (JS, Python, Go): trust config is required on an enrolled host; Go still never authorizes", async t => {
  const e = enrolled(t);
  const receipt = await sealBrowserReceipt({ schema: "aml-dom-receipt/1", decisions: [] });
  const evidence = await createBrowserEvidence(receipt, { url: "https://example.test/" });
  const challenge = createVerificationChallenge({ ttl_ms: 120000 });
  const attestation = await createSessionAttestation({ evidence, challenge });
  await new Promise(resolve => setTimeout(resolve, 10));
  const bundle = e.write("bundle.json", await createWitnessBundle({ evidence, challenge, attestation }));
  const held = e.write("held.json", challenge);
  const good = e.write("good.json", e.config());
  const js = extra => run(process.execPath, ["bin/aml.js", "verify-witness", bundle, held, ...extra], extra.env);
  const py = extra => run("python3", ["independent/python/verify_witness.py", bundle, "--challenge", held, ...extra]);
  assert.equal(js([]).status, 0, "js baseline");
  assert.equal(py([]).status, 0, "python baseline");
  const jsBare = run(process.execPath, ["bin/aml.js", "verify-witness", bundle, held], { AML_TRUST_STATE_DIR: e.state });
  assert.equal(jsBare.status, 2, jsBare.stdout.slice(0, 300));
  assert.ok(reasonsOf(jsBare).includes("AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED"));
  const pyBare = run("python3", ["independent/python/verify_witness.py", bundle, "--challenge", held], { AML_TRUST_STATE_DIR: e.state });
  assert.equal(pyBare.status, 3);
  assert.ok(reasonsOf(pyBare).includes("AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED"));
  const trustFlags = ["--trust-config", good, "--trust-state", e.state, "--single-use-store", e.store];
  const once = js(trustFlags);
  assert.equal(once.status, 0, once.stdout.slice(0, 300));
  const replay = py(trustFlags);
  assert.equal(replay.status, 3, "python replays a bundle node consumed");
  assert.ok(reasonsOf(replay).includes("AML_AUTHZ_ALREADY_CONSUMED"));
  if (!hasGo) return;
  const vector = path.resolve("independent/python/witness-vector.json");
  const g = run(go(), ["--now", "2030-01-01T00:05:00Z", vector], { AML_TRUST_STATE_DIR: e.state });
  assert.equal(g.status, 3);
  assert.equal(g.json.authorized, false);
  assert.equal(g.json.trust.mode, "trust-config");
  assert.ok(g.json.authorization.reasons.includes("AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED"));
  const gTrusted = run(go(), ["--trust-config", good, "--trust-state", e.state, vector]);
  assert.equal(gTrusted.json.trust.trusted, true, gTrusted.stdout.slice(0, 300));
  assert.equal(gTrusted.json.authorized, false, "Go never authorizes, even with a trusted config");
  assert.notEqual(gTrusted.status, 0);
});

test("Python evidence verifiers: config policy pin is ANDed with the flag pin; enrolled host needs a config", t => {
  const archive = "independent/vectors/archive-v1/archive.json";
  const policyFile = "independent/vectors/archive-v1/trusted-policy.json";
  const pin = run("python3", ["independent/python/authorization_cli.py", "policy-sha256", policyFile]).stdout.trim();
  const v = ["independent/python/verify_evidence_archive.py", archive, policyFile];
  assert.equal(run("python3", [...v, "--expected-policy-sha256", pin]).status, 0, "baseline");
  const e = enrolled(t, { policy_sha256: pin });
  const good = e.write("good.json", e.config());
  const bare = run("python3", [...v, "--expected-policy-sha256", pin], { AML_TRUST_STATE_DIR: e.state });
  assert.equal(bare.status, 3);
  assert.ok(reasonsOf(bare).includes("AML_AUTHZ_TRUST_CONFIG_NOT_TRUSTED"));
  const viaConfig = run("python3", [...v, "--trust-config", good, "--trust-state", e.state]);
  assert.equal(viaConfig.status, 0, JSON.stringify([viaConfig.json?.authorization, viaConfig.json?.trust, viaConfig.json?.reason]));
  assert.equal(viaConfig.json.trust.trusted, true);
  const other = enrolled(t, { policy_sha256: "e".repeat(64) });
  const otherCfg = other.write("other.json", other.config());
  const anded = run("python3", [...v, "--expected-policy-sha256", pin, "--trust-config", otherCfg, "--trust-state", other.state]);
  assert.equal(anded.status, 3, "a matching flag pin cannot override the config pin");
  assert.ok(reasonsOf(anded).includes("AML_AUTHZ_POLICY_NOT_PINNED"));
  const store = path.join(e.dir, "store");
  assert.equal(run("python3", [...v, "--trust-config", good, "--trust-state", e.state, "--single-use-store", store]).status, 0);
  const again = run("python3", [...v, "--trust-config", good, "--trust-state", e.state, "--single-use-store", store]);
  assert.equal(again.status, 3);
  assert.ok(reasonsOf(again).includes("AML_AUTHZ_ALREADY_CONSUMED"));
});

test("single use: re-serializing a quorum (whitespace, key order) does not make it a new artifact in either language", t => {
  const e = enrolled(t);
  const good = e.write("good.json", e.config());
  const reorder = v => Array.isArray(v) ? v.map(reorder) : v && typeof v === "object"
    ? Object.fromEntries(Object.keys(v).reverse().map(k => [k, reorder(v[k])])) : v;
  const respelled = e.write("quorum-respelled.json", JSON.stringify(reorder(JSON.parse(fs.readFileSync(QUORUM, "utf8"))), null, 3));
  const flags = ["--policy", HELD, "--trust-config", good, "--trust-state", e.state, "--single-use-store", e.store];
  const first = run(process.execPath, ["bin/aml.js", "verify-signed-quorum", QUORUM, ...flags]);
  assert.equal(first.status, 0, first.stdout.slice(0, 300));
  for (const [label, bin, args] of [["node", process.execPath, ["bin/aml.js", "verify-signed-quorum"]], ["python", "python3", ["independent/python/verify_signed_quorum.py"]]]) {
    const replay = run(bin, [...args, respelled, ...flags]);
    assert.equal(replay.status, 3, `${label}: ${replay.stdout.slice(0, 300)}`);
    assert.ok(reasonsOf(replay).includes("AML_AUTHZ_ALREADY_CONSUMED"), label);
  }
});
