#!/usr/bin/env node

import fs from "node:fs";
import { verifySignedGovernanceStreamTranscript } from "../protocol/governanceTranscriptSignature.js";
import { commandAuthorizationDecision, withCommandAuthorization, commandOutcome, diagnosticOnlyRequested,
  AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// Authorized only when the signed transcript is valid, its key is in the
// caller-supplied trust set (--trusted-fingerprint) and the caller pinned
// the expected key id. Otherwise exit 3 when valid.
const REQUIRED = ["transcript_valid", "trusted_key", "key_id_pinned"];
const DENIALS = { transcript_valid: "AML_AUTHZ_TRANSCRIPT_NOT_VALID", trusted_key: "AML_AUTHZ_KEY_NOT_TRUSTED",
  key_id_pinned: "AML_AUTHZ_KEY_ID_NOT_PINNED" };
const TRUST = ["the supplied trusted fingerprints are current and held by the relying party",
  "a trusted key does not establish real-world signer identity"];
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
process.argv = process.argv.filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG);

function values(name) {
  const result = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    if (process.argv[index] === name && process.argv[index + 1]) result.push(process.argv[index + 1]);
  }
  return result;
}

function value(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? fallback : fallback;
}

const signedPath = process.argv[2];
if (!signedPath) {
  console.error("Usage: aml-governance-transcript-signature-verify <signed.json> [--trusted-fingerprint sha256hex ...] [--require-trusted-key] [--expected-key-id id] [--diagnostic-only]");
  process.exit(1);
}

try {
  const signed = JSON.parse(fs.readFileSync(signedPath, "utf8"));
  const expectedKeyId = value("--expected-key-id") || undefined;
  const verification = verifySignedGovernanceStreamTranscript(signed, {
    trusted_fingerprints: values("--trusted-fingerprint"),
    require_trusted_key: process.argv.includes("--require-trusted-key"),
    expected_key_id: expectedKeyId
  });
  const result = withCommandAuthorization(verification, commandAuthorizationDecision({
    transcript_valid: verification.valid === true,
    trusted_key: verification.trusted_key === true,
    key_id_pinned: typeof expectedKeyId === "string" && expectedKeyId.length > 0 && verification.key_id === expectedKeyId
  }, REQUIRED, DENIALS), TRUST);
  const { output, exitCode } = commandOutcome(result, { diagnosticOnly, invalidCode: 2 });
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  process.exitCode = exitCode;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
