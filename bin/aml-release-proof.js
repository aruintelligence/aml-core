#!/usr/bin/env node

import fs from "node:fs";
import { verifySemanticReleaseProof } from "../compiler/semanticReleaseProof.js";
import { createInTotoSemanticReleaseStatement, verifyInTotoSemanticReleaseStatement } from "../compiler/inTotoSemanticRelease.js";
import { releaseKeyTrustPolicyFingerprint, verifyTrustedSemanticReleaseProof } from "../tooling/releaseKeyTrust.js";
import { decideCommand, diagnosticOnlyRequested, pinMatches, takeOption, AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// Directive 010: `verified` is a precondition, never permission. A proof is
// signed by the key embedded in it, so exit 0 requires a relying-party pin:
// `--expected-sha256` (the exact proof digest) for the plain and in-toto
// forms, or the 64-hex expected release-key policy SHA-256 for `trusted`.
const DENIALS = { verified: "AML_AUTHZ_NOT_VERIFIED", artifact_pinned: "AML_AUTHZ_ARTIFACT_NOT_PINNED",
  policy_pinned: "AML_AUTHZ_POLICY_NOT_PINNED" };
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
const pinOption = takeOption(process.argv.slice(2).filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG), "--expected-sha256");
const expectedSha256 = pinOption.value;
const args = pinOption.rest;

function finish(result, pinName, pinned, trust) {
  const { output, exitCode } = decideCommand(result, {
    consistent: result?.verified === true,
    conditions: { verified: result?.verified === true, [pinName]: result?.verified === true && pinned === true },
    required: ["verified", pinName], denials: DENIALS,
    trust: [...trust, "a key fingerprint binds a key, not a real-world identity"], diagnosticOnly, invalidCode: 1
  });
  console.log(JSON.stringify(output, null, 2));
  process.exit(exitCode);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function usage() {
  console.error("Usage:\n  aml-release-proof <proof.json> [--expected-sha256 HEX] [--diagnostic-only]\n  aml-release-proof trusted <proof.json> <release-key-policy.json> [expected-policy-sha256] [--diagnostic-only]\n  aml-release-proof policy-hash <release-key-policy.json>\n  aml-release-proof in-toto <proof.json>\n  aml-release-proof verify-in-toto <statement.json> [--expected-sha256 HEX] [--diagnostic-only]\nExit: 0 authorized, 3 verified but not authorized (no matching pin), 1 not verified, 2 usage/error.");
}

try {
  if (args.length === 1) {
    const proof = readJson(args[0]);
    const result = verifySemanticReleaseProof(proof);
    finish(result, "artifact_pinned", pinMatches(expectedSha256, result.proof_sha256),
      ["the --expected-sha256 proof digest came from an independently trusted source"]);
  }

  if ((args.length === 3 || args.length === 4) && args[0] === "trusted") {
    const proof = readJson(args[1]);
    const policy = readJson(args[2]);
    const result = verifyTrustedSemanticReleaseProof(proof, policy, { expected_policy_sha256: args[3] ?? null });
    finish(result, "policy_pinned", pinMatches(args[3] ?? null, result.policy_sha256) && result.policy_fingerprint_valid === true,
      ["the expected release-key policy SHA-256 came from an independently trusted source"]);
  }

  if (args.length === 2 && args[0] === "policy-hash") {
    const policy = readJson(args[1]);
    console.log(releaseKeyTrustPolicyFingerprint(policy));
    process.exit(0);
  }

  if (args.length === 2 && args[0] === "in-toto") {
    const proof = readJson(args[1]);
    const statement = createInTotoSemanticReleaseStatement(proof);
    console.log(JSON.stringify(statement, null, 2));
    process.exit(0);
  }

  if (args.length === 2 && args[0] === "verify-in-toto") {
    const statement = readJson(args[1]);
    const result = verifyInTotoSemanticReleaseStatement(statement);
    finish(result, "artifact_pinned", pinMatches(expectedSha256, result.proof_sha256),
      ["the --expected-sha256 proof digest came from an independently trusted source"]);
  }

  usage();
  process.exit(2);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
