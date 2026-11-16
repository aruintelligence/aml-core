#!/usr/bin/env node

import fs from "node:fs";
import { verifySemanticReleaseProof } from "../compiler/semanticReleaseProof.js";
import { decideCommand, diagnosticOnlyRequested, pinMatches, takeOption, AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// Directive 010: a proof is signed by the key embedded in it, so `verified`
// only says the proof is self-consistent. Exit 0 (and output authorized=true)
// requires --trusted-key-sha256 (or AML_TRUSTED_RELEASE_KEY_SHA256) equal to
// the verified signing-key fingerprint. --diagnostic-only keeps exit 0 for a
// verified proof with authorized=false.
const DENIALS = { verified: "AML_AUTHZ_NOT_VERIFIED", signing_key_pinned: "AML_AUTHZ_SIGNING_KEY_NOT_PINNED" };
const diagnosticOnly = diagnosticOnlyRequested(process.argv);

function failUsage() {
  console.error("Usage: node scripts/semantic-release-gate.js <proof.json> [--trusted-key-sha256 HEX] [--diagnostic-only]\nExit: 0 authorized, 3 verified but not authorized, 1 not verified, 2 usage/error.");
  process.exit(2);
}

let proofPath;
let rest;
let trustedKey;
try {
  const taken = takeOption(process.argv.slice(2).filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG), "--trusted-key-sha256");
  [proofPath, ...rest] = taken.rest;
  trustedKey = taken.value ?? (process.env.AML_TRUSTED_RELEASE_KEY_SHA256 || null);
} catch {
  failUsage();
}

function appendOutput(name, value) {
  if (!process.env.GITHUB_OUTPUT) return;
  const safe = value === null || value === undefined ? "" : String(value);
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${safe}\n`);
}

if (!proofPath || rest.length) failUsage();

try {
  const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
  const result = verifySemanticReleaseProof(proof);
  const summary = result.change_summary || { added: 0, removed: 0, changed: 0, unchanged: 0 };

  const verified = result.verified === true;
  const decision = decideCommand(result, {
    consistent: verified,
    conditions: { verified, signing_key_pinned: verified && result.public_key_fingerprint_valid === true &&
      pinMatches(trustedKey, proof.public_key_sha256) },
    required: ["verified", "signing_key_pinned"], denials: DENIALS,
    trust: ["the trusted key SHA-256 came from an independently trusted source",
      "a key fingerprint binds a key, not a real-world identity"], diagnosticOnly, invalidCode: 1
  });
  const outputs = {
    verified: result.verified,
    authorized: decision.output.authorized === true,
    decision_use: decision.output.decision_use ?? "",
    signer: result.signer,
    release_id: result.release_id,
    previous_release_id: result.previous_release_id,
    before_root: result.before_manifest_root_sha256,
    after_root: result.after_manifest_root_sha256,
    lineage_head: result.lineage_head_sha256,
    proof_sha256: result.proof_sha256,
    semantic_changed: result.semantic_changed,
    added: summary.added ?? 0,
    removed: summary.removed ?? 0,
    changed: summary.changed ?? 0,
    unchanged: summary.unchanged ?? 0
  };

  for (const [name, value] of Object.entries(outputs)) appendOutput(name, value);

  console.log(JSON.stringify({
    protocol: "aml-semantic-release-gate-result/1",
    ...outputs,
    authorization: decision.output.authorization,
    remaining_trust_assumptions: decision.output.remaining_trust_assumptions,
    ...(decision.output.diagnostic_only ? { diagnostic_only: true } : {}),
    reason: result.reason ?? null
  }, null, 2));

  process.exit(decision.exitCode);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
