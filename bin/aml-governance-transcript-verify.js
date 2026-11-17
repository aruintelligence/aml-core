#!/usr/bin/env node

import fs from "node:fs";
import { verifyGovernanceStreamTranscript } from "../protocol/governanceTranscript.js";
import { commandAuthorizationDecision, withCommandAuthorization, commandOutcome, diagnosticOnlyRequested,
  AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// An unsigned transcript proves integrity and replay only; this command has
// no trust input and never authorizes: exit 3 when valid, 0 only under
// --diagnostic-only (output authorized:false, NOT AN AUTHORIZATION DECISION).
const REQUIRED = ["transcript_valid", "authenticated_source"];
const DENIALS = { transcript_valid: "AML_AUTHZ_TRANSCRIPT_NOT_VALID",
  authenticated_source: "AML_AUTHZ_TRANSCRIPT_UNAUTHENTICATED" };
const TRUST = ["an unsigned transcript does not identify its producer; use aml-governance-transcript-signature-verify with a trusted key"];
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
const args = process.argv.slice(2).filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG);
const file = args[0] && args[0] !== "-" ? args[0] : null;

try {
  const raw = file ? fs.readFileSync(file, "utf8") : fs.readFileSync(0, "utf8");
  const transcript = JSON.parse(raw);
  const verification = verifyGovernanceStreamTranscript(transcript);
  const result = withCommandAuthorization(verification, commandAuthorizationDecision({
    transcript_valid: verification.valid === true, authenticated_source: false
  }, REQUIRED, DENIALS), TRUST);
  const { output, exitCode } = commandOutcome(result, { diagnosticOnly, invalidCode: 2 });
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  process.exitCode = exitCode;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
