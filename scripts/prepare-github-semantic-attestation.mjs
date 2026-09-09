#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  AML_SEMANTIC_RELEASE_PREDICATE_V1,
  createInTotoSemanticReleaseStatement,
  verifyInTotoSemanticReleaseStatement
} from "../compiler/inTotoSemanticRelease.js";

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) throw new Error(`unexpected argument: ${token}`);
    const key = token.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for --${key}`);
    options[key] = value;
    index += 1;
  }
  return options;
}

export function prepareGitHubSemanticAttestation(proof, outputDir) {
  const statement = createInTotoSemanticReleaseStatement(proof);
  const verification = verifyInTotoSemanticReleaseStatement(statement);
  if (!verification.verified) throw new Error(`generated in-toto statement did not verify: ${verification.reason || "unknown"}`);

  const meaningState = statement.subject[0];
  const target = path.resolve(outputDir);
  fs.mkdirSync(target, { recursive: true });
  const predicatePath = path.join(target, "aml-semantic-release-predicate.json");
  const statementPath = path.join(target, "aml-semantic-release-statement.json");
  const metadataPath = path.join(target, "aml-semantic-release-attestation-input.json");

  fs.writeFileSync(predicatePath, `${JSON.stringify(statement.predicate, null, 2)}\n`);
  fs.writeFileSync(statementPath, `${JSON.stringify(statement, null, 2)}\n`);

  const metadata = {
    schema: "aml-github-semantic-attestation-input/2",
    predicate_type: AML_SEMANTIC_RELEASE_PREDICATE_V1,
    predicate_path: predicatePath,
    statement_path: statementPath,
    meaning_state_name: meaningState.name,
    meaning_state_digest: `sha256:${meaningState.digest.sha256}`,
    github_artifact_subject: "proof-file-bytes-via-actions-attest-subject-path",
    release_id: verification.release_id,
    signer: verification.signer,
    proof_sha256: verification.proof_sha256,
    before_manifest_root_sha256: verification.before_manifest_root_sha256,
    after_manifest_root_sha256: verification.after_manifest_root_sha256,
    lineage_head_sha256: verification.lineage_head_sha256,
    semantic_changed: verification.semantic_changed,
    change_summary: verification.change_summary,
    claim_boundary: "Preparation metadata distinguishes the virtual AML meaning state from the GitHub artifact subject. actions/attest binds the exact proof-file bytes via subject-path; the AML predicate independently binds the verified semantic transition. This is not SLSA build provenance or proof of truth, safety, ethics, legal compliance, certification, or institutional authority."
  };
  fs.writeFileSync(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);
  return { ...metadata, metadata_path: metadataPath };
}

function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (!options.proof) throw new Error("--proof is required");
    if (!options.output) throw new Error("--output is required");
    const proof = JSON.parse(fs.readFileSync(options.proof, "utf8"));
    const result = prepareGitHubSemanticAttestation(proof, options.output);
    console.log(JSON.stringify({ valid: true, ...result }, null, 2));
  } catch (error) {
    console.error(JSON.stringify({ valid: false, error: error instanceof Error ? error.message : String(error) }, null, 2));
    process.exit(1);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
