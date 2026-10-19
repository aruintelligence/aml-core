#!/usr/bin/env node

import fs from "node:fs";
import { verifyOfficialBrandAuthorization } from "../runtime/brandTrust.js";
import { verifyBrandClaim } from "../runtime/brandClaim.js";

const credentialPath = process.argv[2];
const trustRootsPath = process.argv[3] || "BRAND_TRUST_ROOTS.json";
const revocationPath = process.argv[4] || null;
const claimPolicyPath = process.argv[5] || null;

if (!credentialPath) {
  console.error("Usage: aml-brand-verify <credential.json> [brand-trust-roots.json] [revocation-registry.json] [buyer-claim-policy.json]");
  process.exit(1);
}

try {
  const credential = JSON.parse(fs.readFileSync(credentialPath, "utf8"));
  const trustRoots = JSON.parse(fs.readFileSync(trustRootsPath, "utf8"));
  const revocationRegistry = revocationPath ? JSON.parse(fs.readFileSync(revocationPath, "utf8")) : null;
  const result = claimPolicyPath
    ? verifyBrandClaim(credential, trustRoots, revocationRegistry, JSON.parse(fs.readFileSync(claimPolicyPath, "utf8")))
    : verifyOfficialBrandAuthorization(credential, trustRoots, { revocation_registry: revocationRegistry });
  console.log(JSON.stringify(result, null, 2));
  process.exit(claimPolicyPath ? (result.claim_verified ? 0 : 1) : (result.valid && result.official ? 0 : 1));
} catch (error) {
  console.error("Official AML brand verification failed.");
  console.error(error.message);
  process.exit(1);
}
