#!/usr/bin/env node

import fs from "node:fs";
import { verifySemanticReleaseProof } from "../compiler/semanticReleaseProof.js";

const [proofPath, ...rest] = process.argv.slice(2);

function failUsage() {
  console.error("Usage: node scripts/semantic-release-gate.js <proof.json>");
  process.exit(2);
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

  const outputs = {
    verified: result.verified,
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
    reason: result.reason ?? null
  }, null, 2));

  process.exit(result.verified ? 0 : 1);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
