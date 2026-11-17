// Every JS signature verifier accepts exactly one spelling of a signature:
// canonical standard base64 (protocol/strictBase64.js). Node's own decoder is
// lenient, so each alternate spelling below decodes to the SAME signature
// bytes and used to verify; it must now be refused. Canonical signatures
// produced by the existing signers keep verifying (backward compatibility).
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  decodeCanonicalBase64, decodeSignatureBase64, requireSignatureBase64, ED25519_SIGNATURE_BASE64, MAX_SIGNATURE_BYTES
} from "../protocol/strictBase64.js";
import { signCapabilityToken, verifyCapabilityToken, authorizeCapabilityToken } from "../runtime/capabilityToken.js";
import { createThresholdAuthorization, verifyThresholdAuthorization } from "../runtime/thresholdAuthorization.js";
import { signPolicyPack, verifySignedPolicyPack } from "../runtime/policyPack.js";
import { signBrandAuthorization, verifyBrandAuthorization } from "../runtime/brandAuthorization.js";
import { signReleaseProvenanceEvidence, verifySignedReleaseProvenance } from "../protocol/releaseProvenanceSignature.js";
import { createSignedTrustDelegation, verifyTrustDelegation } from "../runtime/trustDelegation.js";
import { createAuditStream, appendAuditEvent } from "../runtime/auditStream.js";
import { signAuditCheckpoint, verifyAuditCheckpoint } from "../runtime/auditAttestation.js";
import { createGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import { signGovernanceStreamTranscript, verifySignedGovernanceStreamTranscript } from "../protocol/governanceTranscriptSignature.js";
import { createGovernanceDisclosure } from "../protocol/governanceDisclosure.js";
import { signGovernanceDisclosureCommitment, verifySignedGovernanceDisclosureCommitment } from "../protocol/governanceDisclosureSignature.js";
import { createGovernancePolicyTransition, signGovernancePolicyTransition, createGovernancePolicyTransitionAuthorization,
  verifyGovernancePolicyTransitionAuthorization } from "../protocol/governancePolicyAuthorization.js";
import { compileAML, signBuildManifest, verifyBuildAttestation, createMeaningManifest, signMeaningManifest,
  verifySignedMeaningManifest } from "../index.js";

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const pair = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return { privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(), publicPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
};

// Alternate spellings of a canonical 88-character Ed25519 signature. Each one
// decodes (leniently) to the same 64 bytes, except the empty/oversized/type cases.
function malformedSpellings(sig) {
  assert.match(sig, ED25519_SIGNATURE_BASE64);
  const i = sig.search(/[+/]/);
  const out = {
    trailing_junk: `${sig}AA`,
    junk_after_padding: `${sig}x`,
    embedded_space: `${sig.slice(0, 44)} ${sig.slice(44)}`,
    embedded_newline: `${sig.slice(0, 44)}\n${sig.slice(44)}`,
    leading_whitespace: ` ${sig}`,
    trailing_newline: `${sig}\n`,
    missing_padding: sig.slice(0, 86),
    single_padding: sig.slice(0, 87),
    extra_padding: `${sig}=`,
    noncanonical_trailing_bits: `${sig.slice(0, 85)}${B64[B64.indexOf(sig[85]) + 1]}==`,
    base64url_alphabet: sig.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    empty: "",
    oversized: `${sig.slice(0, 86).repeat(40)}==`,
    not_a_string: 12345
  };
  if (i >= 0) out.mixed_base64_base64url = `${sig.slice(0, i)}${sig[i] === "+" ? "-" : "_"}${sig.slice(i + 1)}`;
  return out;
}

test("strict decoder: canonical round trips for every length; Node's lenient decoder is the baseline being replaced", () => {
  for (let n = 1; n <= 96; n += 1) {
    const bytes = crypto.randomBytes(n);
    assert.deepEqual(decodeCanonicalBase64(bytes.toString("base64")), bytes, `length ${n}`);
  }
  const sig = crypto.sign(null, Buffer.from("m"), crypto.createPrivateKey(pair().privatePem)).toString("base64");
  const bytes = Buffer.from(sig, "base64");
  for (const [name, value] of Object.entries(malformedSpellings(sig))) {
    assert.equal(decodeSignatureBase64(value), null, name);
    assert.throws(() => requireSignatureBase64(value), /not canonical base64/, name);
    // Baseline: the lenient decoder maps most of these to the same signature bytes.
    if (typeof value === "string" && !["empty", "oversized", "trailing_junk"].includes(name)) {
      assert.deepEqual(Buffer.from(value, "base64"), bytes, `lenient baseline ${name}`);
    }
  }
  assert.equal(decodeSignatureBase64("A".repeat(4 * Math.ceil((MAX_SIGNATURE_BYTES + 3) / 3))), null);
  assert.equal(decodeSignatureBase64(null), null);
  assert.equal(decodeSignatureBase64(undefined), null);
  assert.equal(decodeSignatureBase64("===="), null);
  assert.equal(decodeSignatureBase64("AAAA===="), null);
});

function tokenFixture() {
  const issuer = pair();
  const token = signCapabilityToken({ issuer: "issuer", subject: "executor", audience: "aud", capabilities: ["deploy"],
    issued_at: "2026-01-01T00:00:00Z", expires_at: "2099-01-01T00:00:00Z", nonce: "n-1", session_id: "s-1", intent_sha256: "e".repeat(64) }, issuer.privatePem);
  return { issuer, token };
}

test("capability token: canonical accepted, wrong signature and every alternate spelling refused (verify and authorize)", () => {
  const { token } = tokenFixture();
  assert.equal(verifyCapabilityToken(token).valid, true);
  const opts = { trustedIssuerKeySha256: token.public_key_fingerprint, audience: "aud", subject: "executor", sessionId: "s-1",
    intentSha256: "e".repeat(64), requiredCapability: "deploy" };
  assert.equal(authorizeCapabilityToken(token, { ...opts, consumptionGuard: { type: "aml-capability-consumption/1", consumed: {} } }).authorized, true);

  const other = signCapabilityToken({ ...token, nonce: "n-2" }, pair().privatePem);
  assert.equal(verifyCapabilityToken({ ...token, signature_base64: other.signature_base64 }).reason, "signature_invalid");

  for (const [name, value] of Object.entries(malformedSpellings(token.signature_base64))) {
    const mutated = { ...token, signature_base64: value };
    assert.deepEqual(verifyCapabilityToken(mutated), { valid: false, reason: "signature_invalid" }, name);
    const decision = authorizeCapabilityToken(mutated, { ...opts, consumptionGuard: { type: "aml-capability-consumption/1", consumed: {} } });
    assert.equal(decision.authorized, false, name);
    assert.equal(decision.checks.signature_valid, false, name);
  }
});

test("threshold authorization: alternate spellings of a valid signature are not counted", () => {
  const authorization = createThresholdAuthorization({ action: "publish-policy", policy_hash: "abc" }, [pair().privatePem, pair().privatePem], { threshold: 2 });
  assert.equal(verifyThresholdAuthorization(authorization).valid, true);
  const wrong = structuredClone(authorization);
  wrong.signatures[1].signature_base64 = wrong.signatures[0].signature_base64;
  assert.equal(verifyThresholdAuthorization(wrong).valid_signatures, 1);
  for (const [name, value] of Object.entries(malformedSpellings(authorization.signatures[1].signature_base64))) {
    const mutated = structuredClone(authorization);
    mutated.signatures[1].signature_base64 = value;
    const result = verifyThresholdAuthorization(mutated);
    assert.equal(result.valid, false, name);
    assert.equal(result.valid_signatures, 1, name);
    assert.equal(result.reason, "threshold_not_met", name);
  }
});

const messages = fs.readFileSync("conformance/governance-stream/mixed.ndjson", "utf8")
  .split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => JSON.parse(line));

// [name, build() -> { artifact, get(a) -> sig, set(a, sig) -> a', ok(a') -> boolean }]
const verifiers = [
  ["policy pack", () => {
    const signed = signPolicyPack({ id: "strict_pack", issuer: "issuer", policies: ["restorative_v1"] }, pair().privatePem, { signer: "s", timestamp: "2026-01-01T00:00:00.000Z" });
    return { artifact: signed, get: a => a.attestation.signature_base64,
      set: (a, v) => ({ ...a, attestation: { ...a.attestation, signature_base64: v } }), ok: a => verifySignedPolicyPack(a).verified === true };
  }],
  ["brand authorization", () => {
    const credential = signBrandAuthorization({ grantee: "Example LLC", marks: ["ĀML™"] }, pair().privatePem);
    return { artifact: credential, get: a => a.signature_base64, set: (a, v) => ({ ...a, signature_base64: v }), ok: a => verifyBrandAuthorization(a).valid === true };
  }],
  ["release provenance", () => {
    const evidence = { protocol: "aml-release-provenance-evidence/1", package: "aml-core", version: "1.3.0", control_commit: "a".repeat(40),
      rollback_target: { version: "1.3.0", git_tag: "v1.3.0", commit: "b".repeat(40) }, contract_sha256: { "package.json": "c".repeat(64) },
      evidence_root_sha256: "d".repeat(64), claim_boundary: "fixture" };
    const signed = signReleaseProvenanceEvidence(evidence, pair().privatePem);
    return { artifact: signed, get: a => a.signature.signature_base64,
      set: (a, v) => ({ ...a, signature: { ...a.signature, signature_base64: v } }), ok: a => verifySignedReleaseProvenance(a).signature_valid === true };
  }],
  ["trust delegation", () => {
    const delegate = pair();
    const d = createSignedTrustDelegation({ issuer: "root", delegate: "team", delegate_public_key_pem: delegate.publicPem, capabilities: ["sign-policy"] }, pair().privatePem);
    return { artifact: d, get: a => a.signature_base64, set: (a, v) => ({ ...a, signature_base64: v }), ok: a => verifyTrustDelegation(a).valid === true };
  }],
  ["audit checkpoint", () => {
    const stream = createAuditStream({ stream_id: "strict", timestamp: "2026-01-01T00:00:00.000Z" });
    appendAuditEvent(stream, { event_type: "render", payload: { allowed: true } }, { timestamp: "2026-01-01T00:00:01.000Z" });
    const signed = signAuditCheckpoint(stream, pair().privatePem, { signer: "t", timestamp: "2026-01-01T00:00:02.000Z" });
    return { artifact: signed, get: a => a.attestation.signature_base64,
      set: (a, v) => ({ ...a, attestation: { ...a.attestation, signature_base64: v } }), ok: a => verifyAuditCheckpoint(stream, a).verified === true };
  }],
  ["governance transcript", () => {
    const signed = signGovernanceStreamTranscript(createGovernanceStreamTranscript(messages), pair().privatePem, { key_id: "k", signer: "t", signed_at: "2026-09-10T00:00:00.000Z" });
    return { artifact: signed, get: a => a.signature.signature_base64,
      set: (a, v) => ({ ...a, signature: { ...a.signature, signature_base64: v } }), ok: a => verifySignedGovernanceStreamTranscript(a).signature_valid === true };
  }],
  ["governance disclosure", () => {
    const disclosure = createGovernanceDisclosure(createGovernanceStreamTranscript(messages), [1, 4]);
    const signed = signGovernanceDisclosureCommitment(disclosure, pair().privatePem, { signer: "w" });
    return { artifact: signed, get: a => a.signature.signature_base64,
      set: (a, v) => ({ ...a, signature: { ...a.signature, signature_base64: v } }), ok: a => verifySignedGovernanceDisclosureCommitment(a).signature_valid === true };
  }],
  ["governance policy transition", () => {
    const transition = createGovernancePolicyTransition({ transmission: "t", expected_policy_epoch: 0, previous_policy_sha256: "0".repeat(64), update: { mode: "shadow" } });
    const keys = [pair(), pair()];
    const sigs = keys.map((k, i) => signGovernancePolicyTransition(transition, k.privatePem, { signer: `w${i}` }));
    const fps = sigs.map(s => s.public_key_fingerprint_sha256);
    const auth = createGovernancePolicyTransitionAuthorization(transition, sigs);
    return { artifact: auth, get: a => a.signatures[1].signature_base64,
      set: (a, v) => { const c = structuredClone(a); c.signatures[1].signature_base64 = v; return c; },
      ok: a => verifyGovernancePolicyTransitionAuthorization(a, { threshold: 2, trusted_fingerprints: fps }).valid === true };
  }],
  ["build attestation", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-strict-sig-"));
    const manifestPath = path.join(dir, "build_manifest.json");
    fs.writeFileSync(manifestPath, JSON.stringify({ ok: true }));
    const attestation = signBuildManifest(manifestPath, pair().privatePem, { timestamp: "1970-01-01T00:00:00.000Z", signer: "s" });
    return { artifact: attestation, get: a => a.signature_base64, set: (a, v) => ({ ...a, signature_base64: v }), ok: a => verifyBuildAttestation(a, manifestPath).verified === true };
  }],
  ["meaning manifest attestation", () => {
    const manifest = createMeaningManifest({ "ui/home.aml": `transmission "home" {\n  engram card {\n    purpose: "Explain clearly"\n    attention_cost: 2\n    restoration_value: 5\n  }\n}` });
    const attestation = signMeaningManifest(manifest, pair().privatePem, { signer: "s", timestamp: "2026-01-01T00:00:00.000Z" });
    return { artifact: attestation, get: a => a.signature_base64, set: (a, v) => ({ ...a, signature_base64: v }), ok: a => verifySignedMeaningManifest(a, manifest).verified === true };
  }]
];

for (const [name, build] of verifiers) {
  test(`${name}: canonical signature still verifies; wrong signature and alternate spellings are refused`, () => {
    const { artifact, get, set, ok } = build();
    assert.equal(ok(artifact), true, "canonical (backward compatible)");
    const sig = get(artifact);
    const bytes = Buffer.from(sig, "base64");
    bytes[0] ^= 1;
    assert.equal(ok(set(artifact, bytes.toString("base64"))), false, "wrong signature");
    for (const [variant, value] of Object.entries(malformedSpellings(sig))) {
      assert.equal(ok(set(artifact, value)), false, variant);
    }
  });
}

test("compileAML fixture builds still verify end to end (backward compatibility)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aml-strict-build-"));
  const sourcePath = path.join(dir, "source.aml");
  fs.writeFileSync(sourcePath, `transmission "signed" {\n  engram Card {\n    purpose: "Signed build test."\n    attention_cost: 1\n    restoration_value: 2\n  }\n}\n`);
  compileAML(sourcePath, path.join(dir, "dist"), { timestamp: "1970-01-01T00:00:00.000Z" });
  const manifestPath = path.join(dir, "dist", "build_manifest.json");
  const attestation = signBuildManifest(manifestPath, pair().privatePem, { timestamp: "1970-01-01T00:00:00.000Z", signer: "t" });
  assert.equal(verifyBuildAttestation(attestation, manifestPath).verified, true);
});

test("every committed signature in the repository is already canonical (no existing artifact is newly refused)", () => {
  const roots = ["conformance", "independent", "keys", "evidence", "examples", "registry", "protocol", "pilots", "docs", "test/fixtures", "schema", "schemas", "publications", "reproduction"];
  const files = [];
  const walk = dir => { if (!fs.existsSync(dir)) return; for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name); if (e.isDirectory()) walk(p); else if (/\.(json|jsonl|ndjson|md|html)$/.test(e.name)) files.push(p); } };
  roots.forEach(walk);
  for (const f of fs.readdirSync(".")) if (/\.json$/.test(f)) files.push(f);
  let checked = 0;
  const offenders = [];
  for (const file of files) {
    const text = fs.readFileSync(file, "utf8");
    for (const m of text.matchAll(/"signature_base64"\s*:\s*"([^"]*)"/g)) {
      checked += 1;
      if (decodeSignatureBase64(m[1]) === null) offenders.push(`${file}:${m[1].length}`);
    }
  }
  assert.ok(checked > 0);
  // The only non-canonical values are the deliberate negative conformance vectors.
  assert.deepEqual(offenders.filter(o => !o.startsWith(path.join("conformance", "trust-config", "vectors.json"))), []);
});

test("Python pilot verifier: same canonical-only rule (non-zero unused bits refused, canonical accepted)", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const statement = { n: 1, version: "aml-authorized-execution/1" }; // keys already sorted
  const canonicalBytes = Buffer.from(JSON.stringify(statement)); // matches Python canonical() for this flat ASCII object
  const sig = crypto.sign(null, Buffer.concat([Buffer.from("AML-AUTHORIZED-EXECUTION/1\0"), canonicalBytes]), privateKey).toString("base64");
  const cases = { canonical: sig, ...malformedSpellings(sig) };
  delete cases.not_a_string;
  const script = [
    "import json, sys",
    "sys.path.insert(0, 'pilots/action-boundary')",
    "import authorized_execution as ae",
    "data = json.load(sys.stdin)",
    "out = {}",
    "for name, value in data['cases'].items():",
    "    try:",
    "        ae._verify_signature(data['pem'].encode(), data['statement'], value); out[name] = True",
    "    except ValueError:",
    "        out[name] = False",
    "print(json.dumps(out))"
  ].join("\n");
  const run = spawnSync("python3", ["-c", script], { encoding: "utf8",
    input: JSON.stringify({ pem: publicKey.export({ type: "spki", format: "pem" }), statement, cases }) });
  assert.equal(run.status, 0, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.canonical, true);
  for (const [name, accepted] of Object.entries(result)) if (name !== "canonical") assert.equal(accepted, false, name);
});
