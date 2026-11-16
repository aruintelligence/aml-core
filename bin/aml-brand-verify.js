#!/usr/bin/env node

import fs from "node:fs";
import { verifyOfficialBrandAuthorization } from "../runtime/brandTrust.js";
import { verifyBrandClaim } from "../runtime/brandClaim.js";
import { parseJsonWithoutDuplicateKeys } from "../runtime/strictJson.js";
import { revocationRegistryFingerprint } from "../runtime/revocationRegistry.js";
import { decideCommand, diagnosticOnlyRequested, pinMatches, AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// Directive 010: `valid && official` (a trusted-root key signed it) is a
// precondition, never permission. Without a claim policy, exit 0 also needs a
// revocation registry whose canonical SHA-256 equals the relying party's
// AML_TRUSTED_REVOCATION_REGISTRY_SHA256: an unpinned registry may be an empty
// or rolled-back copy. A buyer claim policy pins the registry head itself
// (claim.revocation_head), so claim_verified carries that pin.
const REQUIRED = ["official", "revocation_checked", "revocation_registry_pinned"];
const CLAIM_REQUIRED = ["claim_verified"];
const DENIALS = { official: "AML_AUTHZ_NOT_OFFICIAL", revocation_checked: "AML_AUTHZ_REVOCATION_NOT_CHECKED",
  revocation_registry_pinned: "AML_AUTHZ_REVOCATION_REGISTRY_NOT_PINNED", claim_verified: "AML_AUTHZ_CLAIM_NOT_VERIFIED" };
const TRUST = ["the trust-root registry file is the relying party's own copy",
  "the pinned revocation registry digest (or claim revocation_head) is current; a pin cannot prove freshness",
  "the verifier host clock", "a key fingerprint binds a key, not a real-world identity"];
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
process.argv = process.argv.filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG);

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
  console.error("Usage: aml-brand-verify <credential.json> [brand-trust-roots.json] [revocation-registry.json] [buyer-claim-policy.json] [--diagnostic-only]\nExit: 0 authorized, 3 official but not authorized, 1 not official or error. Set AML_TRUSTED_REVOCATION_REGISTRY_SHA256.");
  process.exit(1);
}

try {
  const credential = readUnambiguousJson(credentialPath);
  const trustRoots = readUnambiguousJson(trustRootsPath);
  const revocationRegistry = revocationPath ? readUnambiguousJson(revocationPath) : null;
  const result = claimPolicyPath
    ? verifyBrandClaim(credential, trustRoots, revocationRegistry, readUnambiguousJson(claimPolicyPath))
    : verifyOfficialBrandAuthorization(credential, trustRoots, { revocation_registry: revocationRegistry });
  const official = result.valid === true && result.official === true;
  const consistent = claimPolicyPath ? result.claim_verified === true : official;
  const conditions = claimPolicyPath ? { claim_verified: result.claim_verified === true } : {
    official,
    revocation_checked: official && revocationRegistry !== null && result.credential_revocation_checked === true,
    revocation_registry_pinned: revocationRegistry !== null &&
      pinMatches(process.env.AML_TRUSTED_REVOCATION_REGISTRY_SHA256 || null, revocationRegistryFingerprint(revocationRegistry))
  };
  const { output, exitCode } = decideCommand(result, {
    consistent, conditions, required: claimPolicyPath ? CLAIM_REQUIRED : REQUIRED, denials: DENIALS,
    trust: TRUST, diagnosticOnly, invalidCode: 1
  });
  console.log(JSON.stringify(output, null, 2));
  process.exit(exitCode);
} catch (error) {
  console.error("Official AML brand verification failed.");
  console.error(error.message);
  process.exit(1);
}
