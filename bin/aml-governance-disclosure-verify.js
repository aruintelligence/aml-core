#!/usr/bin/env node

import fs from "node:fs";
import { verifyGovernanceDisclosure } from "../protocol/governanceDisclosure.js";
import { commandAuthorizationDecision, withCommandAuthorization, commandOutcome, diagnosticOnlyRequested,
  AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// Authorized only when the proof is valid and its Merkle root was pinned by
// the caller from an independently trusted source (--expected-merkle-root).
const REQUIRED = ["disclosure_valid", "merkle_root_pinned"];
const DENIALS = { disclosure_valid: "AML_AUTHZ_DISCLOSURE_NOT_VALID",
  merkle_root_pinned: "AML_AUTHZ_MERKLE_ROOT_NOT_PINNED" };
const TRUST = ["the pinned Merkle root came from an independently trusted, signed or witnessed source"];
const diagnosticOnly = diagnosticOnlyRequested(process.argv);
process.argv = process.argv.filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG);

function value(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? null : null;
}

const disclosurePath = process.argv[2];
if (!disclosurePath) {
  console.error("Usage: aml-governance-disclosure-verify <disclosure.json> [--expected-merkle-root sha256] [--expected-transcript-root sha256] [--diagnostic-only]");
  process.exit(1);
}

try {
  const disclosure = JSON.parse(fs.readFileSync(disclosurePath, "utf8"));
  const expectedMerkleRoot = value("--expected-merkle-root");
  const verification = verifyGovernanceDisclosure(disclosure, {
    expected_merkle_root: expectedMerkleRoot,
    expected_transcript_root: value("--expected-transcript-root")
  });
  const result = withCommandAuthorization(verification, commandAuthorizationDecision({
    disclosure_valid: verification.valid === true,
    merkle_root_pinned: typeof expectedMerkleRoot === "string" && /^[a-f0-9]{64}$/.test(expectedMerkleRoot) &&
      verification.disclosure_merkle_root_sha256 === expectedMerkleRoot
  }, REQUIRED, DENIALS), TRUST);
  const { output, exitCode } = commandOutcome(result, { diagnosticOnly, invalidCode: 2 });
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  process.exitCode = exitCode;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
