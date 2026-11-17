#!/usr/bin/env node

import fs from "node:fs";
import {
  validateReleaseAuthorizationProfile,
  releaseAuthorizationProfileFingerprint,
  resolveReleaseAuthorizationProfile
} from "../tooling/releaseAuthorizationProfile.js";
import { commandAuthorizationDecision, withCommandAuthorization, commandOutcome, diagnosticOnlyRequested,
  AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// `validate` checks structure only and can never authorize (exit 3 when
// valid). `verify` authorizes only a valid profile whose fingerprint equals
// the caller-pinned expected SHA-256.
const REQUIRED = ["profile_valid", "profile_fingerprint_pinned"];
const DENIALS = { profile_valid: "AML_AUTHZ_PROFILE_NOT_VALID",
  profile_fingerprint_pinned: "AML_AUTHZ_PROFILE_FINGERPRINT_NOT_PINNED" };
const TRUST = ["the expected profile SHA-256 was obtained from an independently trusted source"];
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
const argv = process.argv.slice(2).filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG);
function finish(verification, pinned) {
  const result = withCommandAuthorization(verification, commandAuthorizationDecision({
    profile_valid: verification.valid === true, profile_fingerprint_pinned: pinned === true
  }, REQUIRED, DENIALS), TRUST);
  const { output, exitCode } = commandOutcome(result, { diagnosticOnly, invalidCode: 1 });
  console.log(JSON.stringify(output, null, 2));
  process.exit(exitCode);
}

function read(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function usage() {
  console.error("Usage:\n  aml-release-profile validate <profile.json> [--diagnostic-only]   (exit 3 when valid: structure only, never authorization)\n  aml-release-profile hash <profile.json>\n  aml-release-profile verify <profile.json> <expected-sha256> [--diagnostic-only]");
}

try {
  const [command, file, expected] = argv;
  if (command === "validate" && file && expected === undefined) {
    finish(validateReleaseAuthorizationProfile(read(file)), false);
  }
  if (command === "hash" && file && expected === undefined) {
    console.log(releaseAuthorizationProfileFingerprint(read(file)));
    process.exit(0);
  }
  if (command === "verify" && file && expected) {
    const verification = resolveReleaseAuthorizationProfile(read(file), { expectedProfileSha256: expected });
    finish(verification, /^[a-f0-9]{64}$/.test(expected) && verification.profile_sha256 === expected);
  }
  usage();
  process.exit(2);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
