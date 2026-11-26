#!/usr/bin/env node

import fs from "node:fs";
import { verifyGovernanceDisclosureAgainstSignedCommitment } from "../protocol/governanceDisclosureSignature.js";
import { commandAuthorizationDecision, withCommandAuthorization, commandOutcome, diagnosticOnlyRequested,
  AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// Authorized only when the signed commitment and disclosure are valid, the
// signing key is in the caller-supplied trust set and not revoked, and the
// caller pinned the required signature scope.
const REQUIRED = ["disclosure_valid", "trusted_key", "scope_pinned"];
const DENIALS = { disclosure_valid: "AML_AUTHZ_DISCLOSURE_NOT_VALID", trusted_key: "AML_AUTHZ_KEY_NOT_TRUSTED",
  scope_pinned: "AML_AUTHZ_SCOPE_NOT_PINNED" };
const TRUST = ["the supplied trusted and revoked fingerprint sets are current and held by the relying party",
  "a trusted key does not establish real-world signer identity"];
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
process.argv = process.argv.filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG);

function value(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? null : null;
}
function list(name) {
  const raw = value(name);
  return raw ? raw.split(",").map(v => v.trim()).filter(Boolean) : [];
}

const disclosurePath = process.argv[2];
const signedPath = process.argv[3];
if (!disclosurePath || !signedPath) {
  console.error("Usage: aml-governance-disclosure-signed-verify <disclosure.json> <signed-commitment.json> [--trusted-fingerprints a,b] [--revoked-fingerprints a,b] [--require-trusted-key] [--required-scope scope] [--diagnostic-only]");
  process.exit(1);
}

try {
  const disclosure = JSON.parse(fs.readFileSync(disclosurePath, "utf8"));
  const signed = JSON.parse(fs.readFileSync(signedPath, "utf8"));
  const requiredScope = value("--required-scope") || undefined;
  const verification = verifyGovernanceDisclosureAgainstSignedCommitment(disclosure, signed, {
    trusted_fingerprints: list("--trusted-fingerprints"),
    revoked_fingerprints: list("--revoked-fingerprints"),
    require_trusted_key: process.argv.includes("--require-trusted-key"),
    required_scope: requiredScope
  });
  const result = withCommandAuthorization(verification, commandAuthorizationDecision({
    disclosure_valid: verification.valid === true,
    trusted_key: verification.trusted_key === true,
    scope_pinned: typeof requiredScope === "string" && requiredScope.length > 0 && signed?.signature?.scope === requiredScope
  }, REQUIRED, DENIALS), TRUST);
  const { output, exitCode } = commandOutcome(result, { diagnosticOnly, invalidCode: 2 });
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  process.exitCode = exitCode;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
