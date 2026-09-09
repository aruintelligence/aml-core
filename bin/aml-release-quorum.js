#!/usr/bin/env node

import fs from "node:fs";
import {
  createSemanticReleaseEndorsement,
  fingerprintSemanticReleaseQuorumPolicy,
  verifySemanticReleaseQuorum
} from "../tooling/semanticReleaseQuorum.js";

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function usage() {
  console.error(`Usage:
  aml-release-quorum endorse <proof.json> <private-key.pem> [--signer NAME] [--timestamp RFC3339]
  aml-release-quorum verify <proof.json> <endorsements.json> <policy.json> [--policy-sha256 HEX]
  aml-release-quorum hash-policy <policy.json>`);
}

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (!token.startsWith("--")) throw new Error(`unexpected argument: ${token}`);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${token}`);
    options[token.slice(2)] = value;
    index += 1;
  }
  return options;
}

try {
  const [command, ...args] = process.argv.slice(2);

  if (command === "endorse" && args.length >= 2) {
    const [proofFile, keyFile, ...rest] = args;
    const options = parseOptions(rest);
    const proof = readJson(proofFile);
    const key = fs.readFileSync(keyFile, "utf8");
    const endorsement = createSemanticReleaseEndorsement(proof, key, {
      signer: options.signer ?? null,
      timestamp: options.timestamp ?? new Date().toISOString()
    });
    console.log(JSON.stringify(endorsement, null, 2));
    process.exit(0);
  }

  if (command === "verify" && args.length >= 3) {
    const [proofFile, endorsementsFile, policyFile, ...rest] = args;
    const options = parseOptions(rest);
    const proof = readJson(proofFile);
    const endorsements = readJson(endorsementsFile);
    const policy = readJson(policyFile);
    const result = verifySemanticReleaseQuorum(proof, endorsements, policy, {
      expectedPolicySha256: options["policy-sha256"] ?? null
    });
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.verified ? 0 : 1);
  }

  if (command === "hash-policy" && args.length === 1) {
    console.log(fingerprintSemanticReleaseQuorumPolicy(readJson(args[0])));
    process.exit(0);
  }

  usage();
  process.exit(2);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}
