#!/usr/bin/env node

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import {
  buildGitHubAttestationVerifyArgs,
  verifyGitHubSemanticAttestationEvidence
} from "../tooling/githubSemanticAttestation.js";
import { resolveReleaseAuthorizationProfile } from "../tooling/releaseAuthorizationProfile.js";

function usage() {
  console.error("Usage: aml-github-attestation <proof.json> (--repo OWNER/REPO [ad-hoc trust flags] | --authorization-profile profile.json [--authorization-profile-sha256 HASH] [evidence files])");
}

function parseArgs(argv) {
  if (!argv.length) throw new Error("missing proof file");
  const options = { proofFile: argv[0], allowSelfHosted: false };
  const valueFlags = ["--repo", "--signer-workflow", "--bundle", "--trust-policy", "--trust-policy-sha256", "--quorum-endorsements", "--quorum-policy", "--quorum-policy-sha256", "--authorization-profile", "--authorization-profile-sha256"];
  for (let i = 1; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--allow-self-hosted") {
      options.allowSelfHosted = true;
      options.allowSelfHostedExplicit = true;
      continue;
    }
    if (!valueFlags.includes(token)) throw new Error(`unexpected argument: ${token}`);
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${token}`);
    if (token === "--repo") options.repo = value;
    if (token === "--signer-workflow") options.signerWorkflow = value;
    if (token === "--bundle") options.bundle = value;
    if (token === "--trust-policy") options.trustPolicyFile = value;
    if (token === "--trust-policy-sha256") options.expectedTrustPolicySha256 = value;
    if (token === "--quorum-endorsements") options.quorumEndorsementsFile = value;
    if (token === "--quorum-policy") options.quorumPolicyFile = value;
    if (token === "--quorum-policy-sha256") options.expectedQuorumPolicySha256 = value;
    if (token === "--authorization-profile") options.authorizationProfileFile = value;
    if (token === "--authorization-profile-sha256") options.expectedAuthorizationProfileSha256 = value;
    i += 1;
  }

  if (options.authorizationProfileFile) {
    const conflicting = [
      options.repo ? "--repo" : null,
      options.signerWorkflow ? "--signer-workflow" : null,
      options.allowSelfHostedExplicit ? "--allow-self-hosted" : null,
      options.expectedTrustPolicySha256 ? "--trust-policy-sha256" : null,
      options.expectedQuorumPolicySha256 ? "--quorum-policy-sha256" : null
    ].filter(Boolean);
    if (conflicting.length) throw new Error(`authorization profile conflicts with ad-hoc policy flags: ${conflicting.join(", ")}`);
  } else {
    if (options.expectedAuthorizationProfileSha256) throw new Error("--authorization-profile-sha256 requires --authorization-profile");
    if (!options.repo) throw new Error("--repo is required without --authorization-profile");
    if (options.expectedTrustPolicySha256 && !options.trustPolicyFile) throw new Error("--trust-policy-sha256 requires --trust-policy");
    if (options.expectedQuorumPolicySha256 && !options.quorumPolicyFile) throw new Error("--quorum-policy-sha256 requires --quorum-policy");
  }

  if ((options.quorumPolicyFile && !options.quorumEndorsementsFile) || (options.quorumEndorsementsFile && !options.quorumPolicyFile)) throw new Error("--quorum-policy and --quorum-endorsements must be supplied together");
  return options;
}

try {
  const options = parseArgs(process.argv.slice(2));
  let authorizationProfile = null;
  let authorizationProfileSha256 = null;

  if (options.authorizationProfileFile) {
    authorizationProfile = JSON.parse(fs.readFileSync(options.authorizationProfileFile, "utf8"));
    const resolved = resolveReleaseAuthorizationProfile(authorizationProfile, { expectedProfileSha256: options.expectedAuthorizationProfileSha256 ?? null });
    if (!resolved.valid) throw new Error(resolved.reason);
    authorizationProfile = resolved.profile;
    authorizationProfileSha256 = resolved.profile_sha256;
    options.repo = authorizationProfile.repository;
    options.signerWorkflow = authorizationProfile.signer_workflow;
    options.allowSelfHosted = authorizationProfile.allow_self_hosted;
    options.expectedTrustPolicySha256 = authorizationProfile.release_key_policy_sha256;
    options.expectedQuorumPolicySha256 = authorizationProfile.quorum_policy_sha256;

    if (authorizationProfile.required_layers.release_key_trust && !options.trustPolicyFile) throw new Error("authorization profile requires --trust-policy evidence file");
    if (!authorizationProfile.required_layers.release_key_trust && options.trustPolicyFile) throw new Error("authorization profile forbids release-key trust evidence");
    if (authorizationProfile.required_layers.semantic_release_quorum && (!options.quorumPolicyFile || !options.quorumEndorsementsFile)) throw new Error("authorization profile requires --quorum-policy and --quorum-endorsements evidence files");
    if (!authorizationProfile.required_layers.semantic_release_quorum && (options.quorumPolicyFile || options.quorumEndorsementsFile)) throw new Error("authorization profile forbids quorum evidence");
  }

  const proofBytes = fs.readFileSync(options.proofFile);
  const proof = JSON.parse(proofBytes.toString("utf8"));
  const trustPolicy = options.trustPolicyFile ? JSON.parse(fs.readFileSync(options.trustPolicyFile, "utf8")) : null;
  const quorumEndorsements = options.quorumEndorsementsFile ? JSON.parse(fs.readFileSync(options.quorumEndorsementsFile, "utf8")) : null;
  const quorumPolicy = options.quorumPolicyFile ? JSON.parse(fs.readFileSync(options.quorumPolicyFile, "utf8")) : null;
  const ghArgs = buildGitHubAttestationVerifyArgs(options);
  const gh = spawnSync("gh", ghArgs, { encoding: "utf8", shell: false, maxBuffer: 16 * 1024 * 1024 });

  if (gh.error) {
    console.error(JSON.stringify({ verified: false, reason: gh.error.code === "ENOENT" ? "github_cli_not_found" : "github_cli_execution_error" }, null, 2));
    process.exit(2);
  }
  if (gh.status !== 0) {
    console.error(JSON.stringify({ verified: false, reason: "github_attestation_verification_failed", github_exit_code: gh.status, github_stderr: String(gh.stderr || "").trim() }, null, 2));
    process.exit(1);
  }

  let ghVerification;
  try {
    ghVerification = JSON.parse(gh.stdout);
  } catch {
    console.error(JSON.stringify({ verified: false, reason: "invalid_github_verification_json" }, null, 2));
    process.exit(2);
  }

  const result = verifyGitHubSemanticAttestationEvidence({
    ghVerification,
    proof,
    proofBytes,
    trustPolicy,
    expectedTrustPolicySha256: options.expectedTrustPolicySha256 ?? null,
    quorumEndorsements,
    quorumPolicy,
    expectedQuorumPolicySha256: options.expectedQuorumPolicySha256 ?? null
  });
  console.log(JSON.stringify({
    ...result,
    authorization_profile_required: authorizationProfile !== null,
    authorization_profile_id: authorizationProfile?.profile_id ?? null,
    authorization_profile_sha256: authorizationProfileSha256
  }, null, 2));
  process.exit(result.verified ? 0 : 1);
} catch (error) {
  usage();
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
