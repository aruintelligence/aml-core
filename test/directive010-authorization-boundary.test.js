// Directive 010: across every verifier command, `verified`, `accepted`,
// `quorum_met`, `official` or a valid signature is only a precondition. Exit 0
// requires the complete authorization decision, which needs a relying-party
// pin (artifact digest, signing-key fingerprint, policy digest or profile
// digest). Each block: the unpinned/attacker case is consistent but exits 3,
// the pinned positive control exits 0, a wrong pin exits 3, and
// --diagnostic-only exits 0 labelled NOT AN AUTHORIZATION DECISION.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  executeAccountableIntent, signExecutionReceipt, signPolicyPack, createAuditStream, appendAuditEvent,
  createMeaningManifest, signMeaningManifest, createMeaningLineage, appendMeaningLineage,
  createSemanticReleaseProof, createInTotoSemanticReleaseStatement, AML_SEMANTIC_RELEASE_PREDICATE_V1,
  SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL, createSemanticReleaseEndorsement, fingerprintSemanticReleaseQuorumPolicy,
  RELEASE_AUTHORIZATION_PROFILE_PROTOCOL, releaseAuthorizationProfileFingerprint
} from "../index.js";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import { signGovernanceStreamTranscript } from "../protocol/governanceTranscriptSignature.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const NOT_AUTH = "NOT AN AUTHORIZATION DECISION";
const ZERO = "0".repeat(64);

function tmp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-d010-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return (name, value) => {
    const file = path.join(dir, name);
    fs.writeFileSync(file, typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`);
    return file;
  };
}
function node(args, options = {}) {
  const out = spawnSync(process.execPath, args, { encoding: "utf8", ...options });
  let json = null;
  try { json = JSON.parse(out.stdout); } catch { /* text output */ }
  return { status: out.status, json, stdout: out.stdout, stderr: out.stderr };
}
function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return { pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    sha256: crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex") };
}
function assertContract(run, { unpinned, pinned, wrong, diagnostic, reason }) {
  const u = run(unpinned);
  assert.equal(u.status, 3, `unpinned: ${u.stdout}${u.stderr}`);
  assert.equal(u.json.authorized, false);
  assert.equal(u.json.decision_use, NOT_AUTH);
  if (reason) assert.ok(u.json.authorization.reasons.includes(reason), u.json.authorization.reasons.join());
  const p = run(pinned);
  assert.equal(p.status, 0, `pinned: ${p.stdout}${p.stderr}`);
  assert.equal(p.json.authorized, true);
  assert.equal(p.json.authorization.authorized, true);
  assert.deepEqual(p.json.authorization.reasons, ["AML_AUTHZ_ALLOW"]);
  if (wrong) assert.equal(run(wrong).status, 3, "wrong pin");
  if (diagnostic) {
    const d = run(diagnostic);
    assert.equal(d.status, 0, `diagnostic: ${d.stdout}`);
    assert.equal(d.json.authorized, false);
    assert.equal(d.json.decision_use, NOT_AUTH);
  }
}

const intent = { transmission: "d010", nodes: [{ type: "engram", identifier: "card",
  properties: { purpose: "Explain the result.", attention_cost: 1, restoration_value: 5 } }] };

test("aml verify-signed-receipt authorizes only a pinned signing key; a re-signed receipt is not authorized", t => {
  const save = tmp(t);
  const owner = keyPair();
  const attacker = keyPair();
  const receipt = executeAccountableIntent(intent, { timestamp: "2030-01-01T00:00:00.000Z" });
  const signed = save("signed.json", signExecutionReceipt(receipt, owner.pem));
  const forged = save("forged.json", signExecutionReceipt(receipt, attacker.pem));
  const run = extra => node(["bin/aml.js", "verify-signed-receipt", ...extra]);
  assertContract(run, { unpinned: [signed], pinned: [signed, "--trusted-key-sha256", owner.sha256],
    wrong: [signed, "--trusted-key-sha256", ZERO], diagnostic: [signed, "--diagnostic-only"],
    reason: "AML_AUTHZ_SIGNING_KEY_NOT_PINNED" });
  const f = run([forged, "--trusted-key-sha256", owner.sha256]);
  assert.equal(f.status, 3, "attacker key signature verifies but is not the pinned key");
  assert.equal(f.json.verified, true);
});

test("aml verify-receipt and verify-policy-pack and verify-audit need pins", t => {
  const save = tmp(t);
  const receipt = executeAccountableIntent(intent, { timestamp: "2030-01-01T00:00:00.000Z" });
  const receiptFile = save("receipt.json", receipt);
  assertContract(extra => node(["bin/aml.js", "verify-receipt", ...extra]), {
    unpinned: [receiptFile], pinned: [receiptFile, "--expected-sha256", receipt.receipt_sha256],
    wrong: [receiptFile, "--expected-sha256", ZERO], diagnostic: [receiptFile, "--diagnostic-only"],
    reason: "AML_AUTHZ_ARTIFACT_NOT_PINNED" });

  const owner = keyPair();
  const pack = save("pack.json", signPolicyPack({ id: "d010_pack", issuer: "test", policies: ["restorative_v1"] }, owner.pem,
    { timestamp: "2030-01-01T00:00:00.000Z" }));
  assertContract(extra => node(["bin/aml.js", "verify-policy-pack", ...extra]), {
    unpinned: [pack], pinned: [pack, "--trusted-key-sha256", owner.sha256],
    wrong: [pack, "--trusted-key-sha256", ZERO], diagnostic: [pack, "--diagnostic-only"] });

  const stream = createAuditStream({ stream_id: "d010", timestamp: "2030-01-01T00:00:00.000Z" });
  appendAuditEvent(stream, { event_type: "render", payload: { allowed: true } }, { timestamp: "2030-01-01T00:00:00.000Z" });
  const streamFile = save("stream.json", stream);
  assertContract(extra => node(["bin/aml.js", "verify-audit", ...extra]), {
    unpinned: [streamFile], pinned: [streamFile, "--expected-sha256", stream.entries.at(-1).entry_hash],
    wrong: [streamFile, "--expected-sha256", ZERO], diagnostic: [streamFile, "--diagnostic-only"] });
  // A truncated stream is still hash-consistent; the head pin rejects it.
  const truncated = structuredClone(stream);
  appendAuditEvent(stream, { event_type: "render", payload: { allowed: false } }, { timestamp: "2030-01-01T00:00:01.000Z" });
  const longFile = save("long.json", stream);
  const t1 = node(["bin/aml.js", "verify-audit", save("truncated.json", truncated), "--expected-sha256", stream.entries.at(-1).entry_hash]);
  assert.equal(t1.status, 3, "rolled-back audit stream is not authorized");
  assert.equal(node(["bin/aml.js", "verify-audit", longFile, "--expected-sha256", stream.entries.at(-1).entry_hash]).status, 0);
});

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(JSON.parse);
const witnessTranscript = createGovernanceStreamTranscript(messages);
function witness(key, name) {
  return signGovernanceStreamTranscript(witnessTranscript, key.pem, { signer: name, scope: "governance-witness" });
}
const policySha = policy => crypto.createHash("sha256").update(canonicalJSONStringify(policy)).digest("hex");

test("aml-governance-witness-quorum: a self-chosen policy with self-signed witnesses never authorizes", t => {
  const save = tmp(t);
  // Exploit (d35a6b1 exit 0): the input file carries its own policy; with no
  // trusted list, any two fresh keys meet a threshold of 2.
  const forged = { policy: { threshold: 2 }, signed_transcripts: [witness(keyPair(), "x"), witness(keyPair(), "y")] };
  const forgedFile = save("forged.json", forged);
  const run = extra => node(["bin/aml-governance-witness-quorum.js", ...extra]);
  const exploit = run([forgedFile]);
  assert.equal(exploit.status, 3, exploit.stdout);
  assert.equal(exploit.json.quorum_met, true);
  assert.deepEqual(exploit.json.authorization.reasons, ["AML_AUTHZ_POLICY_NOT_PINNED", "AML_AUTHZ_POLICY_TRUSTS_ANY_KEY"]);
  // Even when the relying party pins that permissive policy, it trusts any key.
  const pinnedPermissive = run([forgedFile, "--expected-policy-sha256", policySha(forged.policy)]);
  assert.equal(pinnedPermissive.status, 3);
  assert.deepEqual(pinnedPermissive.json.authorization.reasons, ["AML_AUTHZ_POLICY_TRUSTS_ANY_KEY"]);

  const a = keyPair(); const b = keyPair();
  const policy = { threshold: 2, trusted_fingerprints: [], required_scope: "governance-witness" };
  const signedA = witness(a, "a"); const signedB = witness(b, "b");
  policy.trusted_fingerprints = [signedA.signature.public_key_fingerprint_sha256, signedB.signature.public_key_fingerprint_sha256];
  const good = save("good.json", { policy, signed_transcripts: [signedA, signedB] });
  assertContract(run, { unpinned: [good], pinned: [good, "--expected-policy-sha256", policySha(policy)],
    wrong: [good, "--expected-policy-sha256", ZERO], diagnostic: [good, "--diagnostic-only"],
    reason: "AML_AUTHZ_POLICY_NOT_PINNED" });
  // Same trusted keys, but the file lowers the threshold: the pin no longer matches.
  const lowered = save("lowered.json", { policy: { ...policy, threshold: 1 }, signed_transcripts: [signedA] });
  assert.equal(run([lowered, "--expected-policy-sha256", policySha(policy)]).status, 3);
  const unmet = save("unmet.json", { policy, signed_transcripts: [signedA] });
  assert.equal(run([unmet, "--expected-policy-sha256", policySha(policy)]).status, 2);
});

function releaseFixture() {
  const releaseKey = keyPair();
  const before = { "ui/app.aml": `transmission "app" { engram card { purpose: "before" attention_cost: 1 restoration_value: 3 } }` };
  const after = { "ui/app.aml": `transmission "app" { engram card { purpose: "after" attention_cost: 2 restoration_value: 4 } }` };
  const bm = createMeaningManifest(before); const am = createMeaningManifest(after);
  const ba = signMeaningManifest(bm, releaseKey.pem, { signer: "release-bot", timestamp: "2026-09-09T13:00:00.000Z" });
  const aa = signMeaningManifest(am, releaseKey.pem, { signer: "release-bot", timestamp: "2026-09-09T13:05:00.000Z" });
  let lineage = appendMeaningLineage(createMeaningLineage(), bm, ba);
  lineage = appendMeaningLineage(lineage, am, aa);
  const proof = createSemanticReleaseProof({ before_manifest: bm, before_attestation: ba, after_manifest: am,
    after_attestation: aa, lineage, before_sources: before, after_sources: after, private_key_pem: releaseKey.pem,
    signer: "release-bot", timestamp: "2026-09-09T13:10:00.000Z", release_id: "d010-1" });
  return { releaseKey, proof, manifest: am, attestation: aa };
}

test("semantic-release-gate and aml-meaning verify-attestation authorize only a pinned release key", t => {
  const save = tmp(t);
  const f = releaseFixture();
  const proofFile = save("proof.json", f.proof);
  assertContract(extra => node(["scripts/semantic-release-gate.js", ...extra], { env: { ...process.env, GITHUB_OUTPUT: "" } }), {
    unpinned: [proofFile], pinned: [proofFile, "--trusted-key-sha256", f.releaseKey.sha256],
    wrong: [proofFile, "--trusted-key-sha256", ZERO], diagnostic: [proofFile, "--diagnostic-only"],
    reason: "AML_AUTHZ_SIGNING_KEY_NOT_PINNED" });
  // An attacker's self-made proof verifies under its own embedded key.
  const forged = releaseFixture();
  const forgedRun = node(["scripts/semantic-release-gate.js", save("forged.json", forged.proof), "--trusted-key-sha256", f.releaseKey.sha256]);
  assert.equal(forgedRun.status, 3);
  assert.equal(forgedRun.json.verified, true);

  const att = save("att.json", f.attestation); const man = save("man.json", f.manifest);
  assertContract(extra => node(["bin/aml-meaning.js", "verify-attestation", ...extra]), {
    unpinned: [att, man], pinned: [att, man, "--trusted-key-sha256", f.releaseKey.sha256],
    wrong: [att, man, "--trusted-key-sha256", ZERO], diagnostic: [att, man, "--diagnostic-only"] });
});

test("aml-release-quorum verify authorizes only under a pinned quorum policy", t => {
  const save = tmp(t);
  const f = releaseFixture();
  const approvers = [keyPair(), keyPair()];
  const policy = { protocol: SEMANTIC_RELEASE_QUORUM_POLICY_PROTOCOL, policy_id: "board", threshold: 2,
    trusted_keys: approvers.map((k, i) => ({ public_key_sha256: k.sha256, signer: `approver-${i + 1}` })) };
  const endorsements = approvers.map((k, i) => createSemanticReleaseEndorsement(f.proof, k.pem,
    { signer: `approver-${i + 1}`, timestamp: "2026-09-09T13:11:00.000Z" }));
  const files = [save("proof.json", f.proof), save("end.json", endorsements), save("policy.json", policy)];
  const pin = fingerprintSemanticReleaseQuorumPolicy(policy);
  const run = extra => node(["bin/aml-release-quorum.js", "verify", ...extra]);
  assertContract(run, { unpinned: files, pinned: [...files, "--policy-sha256", pin],
    diagnostic: [...files, "--diagnostic-only"], reason: "AML_AUTHZ_POLICY_NOT_PINNED" });
  assert.equal(run([...files, "--policy-sha256", ZERO]).status, 1, "a mismatched policy pin is a verification failure");
  // Exploit (d35a6b1 exit 0): attacker-written policy trusting attacker keys.
  const rogue = [keyPair(), keyPair()];
  const roguePolicy = { ...policy, trusted_keys: rogue.map((k, i) => ({ public_key_sha256: k.sha256, signer: `approver-${i + 1}` })) };
  const rogueEnd = rogue.map((k, i) => createSemanticReleaseEndorsement(f.proof, k.pem, { signer: `approver-${i + 1}`, timestamp: "2026-09-09T13:11:00.000Z" }));
  const rogueRun = run([files[0], save("rogue-end.json", rogueEnd), save("rogue-policy.json", roguePolicy)]);
  assert.equal(rogueRun.status, 3);
  assert.equal(rogueRun.json.verified, true);
  assert.equal(run([files[0], save("rogue-end2.json", rogueEnd), save("rogue-policy2.json", roguePolicy), "--policy-sha256", pin]).status, 1);
});

test("aml-github-attestation authorizes only with a pinned authorization profile", t => {
  const save = tmp(t);
  const f = releaseFixture();
  const proofBytes = Buffer.from(`${JSON.stringify(f.proof, null, 2)}\n`);
  const proofFile = save("release-proof.json", proofBytes.toString("utf8"));
  const statement = createInTotoSemanticReleaseStatement(f.proof);
  const ghOut = [{ verificationResult: { statement: { _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "release-proof.json", digest: { sha256: crypto.createHash("sha256").update(proofBytes).digest("hex") } }],
    predicateType: AML_SEMANTIC_RELEASE_PREDICATE_V1, predicate: structuredClone(statement.predicate) } } }];
  const binDir = path.dirname(save("gh-out.json", ghOut));
  const fakeGh = path.join(binDir, "gh");
  fs.writeFileSync(fakeGh, `#!/bin/sh\ncat "${path.join(binDir, "gh-out.json")}"\n`, { mode: 0o755 });
  const env = { ...process.env, PATH: `${binDir}${path.delimiter}${process.env.PATH}` };
  const profile = { protocol: RELEASE_AUTHORIZATION_PROFILE_PROTOCOL, profile_id: "d010", repository: "acme/app",
    signer_workflow: "acme/app/.github/workflows/release.yml", allow_self_hosted: false,
    predicate_type: AML_SEMANTIC_RELEASE_PREDICATE_V1,
    required_layers: { github_attestation: true, semantic_release_proof: true, release_key_trust: false, semantic_release_quorum: false },
    release_key_policy_sha256: null, quorum_policy_sha256: null };
  const profileFile = save("profile.json", profile);
  const run = extra => node(["bin/aml-github-attestation.js", proofFile, ...extra], { env });
  const adhoc = run(["--repo", "acme/app"]);
  assert.equal(adhoc.status, 3, adhoc.stdout + adhoc.stderr);
  assert.equal(adhoc.json.verified, true);
  assert.ok(adhoc.json.authorization.reasons.includes("AML_AUTHZ_AUTHORIZATION_PROFILE_NOT_PINNED"));
  assertContract(run, { unpinned: ["--authorization-profile", profileFile],
    pinned: ["--authorization-profile", profileFile, "--authorization-profile-sha256", releaseAuthorizationProfileFingerprint(profile)],
    diagnostic: ["--authorization-profile", profileFile, "--diagnostic-only"] });
});

test("aml verify (build manifest) authorizes only a pinned manifest digest", t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-d010-build-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const out = path.join(dir, "out");
  assert.equal(node(["bin/aml.js", "compile", "examples/simple.aml", out]).status, 0);
  const manifest = path.join(out, "build_manifest.json");
  const pin = crypto.createHash("sha256").update(fs.readFileSync(manifest)).digest("hex");
  const run = extra => node(["bin/aml.js", "verify", manifest, ...extra]);
  const unpinned = run([]);
  assert.equal(unpinned.status, 3, unpinned.stdout);
  assert.match(unpinned.stdout, /Verified: true/);
  assert.match(unpinned.stdout, /Authorized: false/);
  assert.match(unpinned.stdout, /Decision use: NOT AN AUTHORIZATION DECISION/);
  const pinned = run(["--expected-sha256", pin]);
  assert.equal(pinned.status, 0, pinned.stdout);
  assert.match(pinned.stdout, /Authorized: true/);
  assert.equal(run(["--expected-sha256", ZERO]).status, 3);
  const diagnostic = run(["--diagnostic-only"]);
  assert.equal(diagnostic.status, 0);
  assert.match(diagnostic.stdout, /Authorized: false/);
});
