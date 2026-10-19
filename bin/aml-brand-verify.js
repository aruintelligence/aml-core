#!/usr/bin/env node

import fs from "node:fs";
import { verifyOfficialBrandAuthorization } from "../runtime/brandTrust.js";
import { verifyBrandClaim } from "../runtime/brandClaim.js";
import { parseJsonWithoutDuplicateKeys } from "../runtime/strictJson.js";

function readUnambiguousJson(filePath) {
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
    .decode(fs.readFileSync(filePath));
  return parseJsonWithoutDuplicateKeys(source);
}

const credentialPath = process.argv[2];
const trustRootsPath = process.argv[3] || "BRAND_TRUST_ROOTS.json";
const revocationPath = process.argv[4] || null;
const claimPolicyPath = process.argv[5] || null;

if (!credentialPath) {
  console.error("Usage: aml-brand-verify <credential.json> [brand-trust-roots.json] [revocation-registry.json] [buyer-claim-policy.json]");
  process.exit(1);
}

try {
  const credential = readUnambiguousJson(credentialPath);
  const trustRoots = readUnambiguousJson(trustRootsPath);
  const revocationRegistry = revocationPath ? readUnambiguousJson(revocationPath) : null;
  const result = claimPolicyPath
    ? verifyBrandClaim(credential, trustRoots, revocationRegistry, readUnambiguousJson(claimPolicyPath))
    : verifyOfficialBrandAuthorization(credential, trustRoots, { revocation_registry: revocationRegistry });
  console.log(JSON.stringify(result, null, 2));
  process.exit(claimPolicyPath ? (result.claim_verified ? 0 : 1) : (result.valid && result.official ? 0 : 1));
} catch (error) {
  console.error("Official AML brand verification failed.");
  console.error(error.message);
  process.exit(1);
}
