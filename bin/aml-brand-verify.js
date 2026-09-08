#!/usr/bin/env node

import fs from "node:fs";
import { verifyOfficialBrandAuthorization } from "../runtime/brandTrust.js";

const credentialPath = process.argv[2];
const trustRootsPath = process.argv[3] || "BRAND_TRUST_ROOTS.json";
const revocationPath = process.argv[4] || null;

if (!credentialPath) {
  console.error("Usage: aml-brand-verify <credential.json> [brand-trust-roots.json] [revocation-registry.json]");
  process.exit(1);
}

try {
  const credential = JSON.parse(fs.readFileSync(credentialPath, "utf8"));
  const trustRoots = JSON.parse(fs.readFileSync(trustRootsPath, "utf8"));
  const revocationRegistry = revocationPath ? JSON.parse(fs.readFileSync(revocationPath, "utf8")) : null;
  const result = verifyOfficialBrandAuthorization(credential, trustRoots, {
    now: process.env.AML_VERIFY_AT || null,
    revocation_registry: revocationRegistry,
    expected_issuer: process.env.AML_EXPECTED_BRAND_ISSUER || trustRoots.owner || "ĀRU Intelligence Inc."
  });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.valid && result.official ? 0 : 1);
} catch (error) {
  console.error("Official AML brand verification failed.");
  console.error(error.message);
  process.exit(1);
}
