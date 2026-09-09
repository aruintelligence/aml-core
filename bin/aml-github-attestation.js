#!/usr/bin/env node

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import {
  buildGitHubAttestationVerifyArgs,
  verifyGitHubSemanticAttestationEvidence
} from "../tooling/githubSemanticAttestation.js";

function usage() {
  console.error("Usage: aml-github-attestation <proof.json> --repo OWNER/REPO [--trust-policy policy.json] [--signer-workflow WORKFLOW] [--bundle BUNDLE.jsonl] [--allow-self-hosted]");
}

function parseArgs(argv) {
  if (!argv.length) throw new Error("missing proof file");
  const options = { proofFile: argv[0], allowSelfHosted: false };
  for (let i = 1; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--allow-self-hosted") {
      options.allowSelfHosted = true;
      continue;
    }
    if (!["--repo", "--signer-workflow", "--bundle", "--trust-policy"].includes(token)) throw new Error(`unexpected argument: ${token}`);
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${token}`);
    if (token === "--repo") options.repo = value;
    if (token === "--signer-workflow") options.signerWorkflow = value;
    if (token === "--bundle") options.bundle = value;
    if (token === "--trust-policy") options.trustPolicyFile = value;
    i += 1;
  }
  if (!options.repo) throw new Error("--repo is required");
  return options;
}

try {
  const options = parseArgs(process.argv.slice(2));
  const proofBytes = fs.readFileSync(options.proofFile);
  const proof = JSON.parse(proofBytes.toString("utf8"));
  const trustPolicy = options.trustPolicyFile ? JSON.parse(fs.readFileSync(options.trustPolicyFile, "utf8")) : null;
  const ghArgs = buildGitHubAttestationVerifyArgs(options);
  const gh = spawnSync("gh", ghArgs, { encoding: "utf8", shell: false, maxBuffer: 16 * 1024 * 1024 });

  if (gh.error) {
    console.error(JSON.stringify({ verified: false, reason: gh.error.code === "ENOENT" ? "github_cli_not_found" : "github_cli_execution_error" }, null, 2));
    process.exit(2);
  }
  if (gh.status !== 0) {
    console.error(JSON.stringify({
      verified: false,
      reason: "github_attestation_verification_failed",
      github_exit_code: gh.status,
      github_stderr: String(gh.stderr || "").trim()
    }, null, 2));
    process.exit(1);
  }

  let ghVerification;
  try {
    ghVerification = JSON.parse(gh.stdout);
  } catch {
    console.error(JSON.stringify({ verified: false, reason: "invalid_github_verification_json" }, null, 2));
    process.exit(2);
  }

  const result = verifyGitHubSemanticAttestationEvidence({ ghVerification, proof, proofBytes, trustPolicy });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.verified ? 0 : 1);
} catch (error) {
  usage();
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
