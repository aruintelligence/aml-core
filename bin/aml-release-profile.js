#!/usr/bin/env node

import fs from "node:fs";
import {
  validateReleaseAuthorizationProfile,
  releaseAuthorizationProfileFingerprint,
  resolveReleaseAuthorizationProfile
} from "../tooling/releaseAuthorizationProfile.js";

function read(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function usage() {
  console.error("Usage:\n  aml-release-profile validate <profile.json>\n  aml-release-profile hash <profile.json>\n  aml-release-profile verify <profile.json> <expected-sha256>");
}

try {
  const [command, file, expected] = process.argv.slice(2);
  if (command === "validate" && file && expected === undefined) {
    const result = validateReleaseAuthorizationProfile(read(file));
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  }
  if (command === "hash" && file && expected === undefined) {
    console.log(releaseAuthorizationProfileFingerprint(read(file)));
    process.exit(0);
  }
  if (command === "verify" && file && expected) {
    const result = resolveReleaseAuthorizationProfile(read(file), { expectedProfileSha256: expected });
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  }
  usage();
  process.exit(2);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
