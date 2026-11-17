#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";
import { evaluateGovernanceWitnessQuorum } from "../protocol/governanceWitnessQuorum.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { decideCommand, diagnosticOnlyRequested, pinMatches, takeOption,
  AML_DIAGNOSTIC_ONLY_FLAG } from "../runtime/commandAuthorization.js";

// Directive 010: `quorum_met` is a precondition, never permission. The quorum
// input file carries its own policy, so whoever writes the file chooses the
// threshold and (with an empty trusted_fingerprints list) can self-sign every
// witness. Exit 0 requires: quorum met, the policy's canonical SHA-256 equal
// to the relying party's --expected-policy-sha256, a non-empty trusted key
// list in that policy, and no conflicting eligible transcript roots.
const REQUIRED = ["quorum_met", "policy_pinned", "trusted_keys_required", "no_conflicting_roots"];
const DENIALS = { quorum_met: "AML_AUTHZ_QUORUM_NOT_MET", policy_pinned: "AML_AUTHZ_POLICY_NOT_PINNED",
  trusted_keys_required: "AML_AUTHZ_POLICY_TRUSTS_ANY_KEY", no_conflicting_roots: "AML_AUTHZ_CONFLICTING_ROOTS" };
const TRUST = ["the expected policy SHA-256 came from an independently trusted source",
  "holders of the trusted witness keys are distinct and uncompromised",
  "a key fingerprint binds a key, not a real-world identity"];

function governanceWitnessPolicySha256(policy) {
  return crypto.createHash("sha256").update(canonicalJSONStringify(policy ?? {})).digest("hex");
}

const diagnosticOnly = diagnosticOnlyRequested(process.argv);
let argv;
let expectedPolicySha256;
try {
  const taken = takeOption(process.argv.slice(2).filter(arg => arg !== AML_DIAGNOSTIC_ONLY_FLAG), "--expected-policy-sha256");
  argv = taken.rest;
  expectedPolicySha256 = taken.value;
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
const inputPath = argv[0];
if (!inputPath || argv.length !== 1) {
  console.error("Usage: aml-governance-witness-quorum <quorum-input.json> [--expected-policy-sha256 HEX] [--diagnostic-only]\nExit: 0 authorized, 3 quorum met but not authorized, 2 quorum not met, 1 usage/error.");
  process.exit(1);
}

try {
  const input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  if (!Array.isArray(input.signed_transcripts)) throw new Error("signed_transcripts array is required");
  const policy = input.policy || {};
  const result = evaluateGovernanceWitnessQuorum(input.signed_transcripts, policy);
  const policySha256 = governanceWitnessPolicySha256(policy);
  const met = result.quorum_met === true;
  const { output, exitCode } = decideCommand({ ...result, policy_sha256: policySha256 }, {
    consistent: met,
    conditions: {
      quorum_met: met,
      policy_pinned: pinMatches(expectedPolicySha256, policySha256),
      trusted_keys_required: Array.isArray(result.policy?.trusted_fingerprints) && result.policy.trusted_fingerprints.length > 0,
      no_conflicting_roots: result.conflicting_eligible_roots === false
    },
    required: REQUIRED, denials: DENIALS, trust: TRUST, diagnosticOnly, invalidCode: 2
  });
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  process.exitCode = exitCode;
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
