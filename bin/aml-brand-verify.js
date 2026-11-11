#!/usr/bin/env node

import { finishConsistencyCommand, diagnosticOnlyRequested } from "../runtime/commandAuthorization.js";
import fs from "node:fs";
import { verifyOfficialBrandAuthorization } from "../runtime/brandTrust.js";
import { verifyBrandClaim } from "../runtime/brandClaim.js";
import { parseJsonWithoutDuplicateKeys } from "../runtime/strictJson.js";

function readUnambiguousJson(filePath) {
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
    .decode(fs.readFileSync(filePath));
  return parseJsonWithoutDuplicateKeys(source);
}

const diagnosticOnly = diagnosticOnlyRequested(process.argv.slice(2));
const argv = process.argv.slice(2).filter(arg => arg !== "--diagnostic-only");
const credentialPath = argv[0];
const trustRootsPath = argv[1] || "BRAND_TRUST_ROOTS.json";
const revocationPath = argv[2] || null;
const claimPolicyPath = argv[3] || null;

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
  await finishConsistencyCommand(result, claimPolicyPath ? result.claim_verified === true :
    result.valid === true && result.official === true, { diagnosticOnly });
} catch (error) {
  console.error("Official AML brand verification failed.");
  console.error(error.message);
  process.exit(1);
}
