#!/usr/bin/env node

import fs from "node:fs";
import { signGovernanceDisclosureCommitment } from "../protocol/governanceDisclosureSignature.js";

function value(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? fallback : fallback;
}

const disclosurePath = process.argv[2];
const keyPath = value("--key");
if (!disclosurePath || !keyPath) {
  console.error("Usage: aml-governance-disclosure-sign <disclosure.json> --key <ed25519-private.pem> [--key-id id] [--signer name] [--scope scope] [--signed-at timestamp]");
  process.exit(1);
}

try {
  const disclosure = JSON.parse(fs.readFileSync(disclosurePath, "utf8"));
  const privateKeyPem = fs.readFileSync(keyPath, "utf8");
  const signed = signGovernanceDisclosureCommitment(disclosure, privateKeyPem, {
    key_id: value("--key-id") || undefined,
    signer: value("--signer") || undefined,
    scope: value("--scope", "governance-disclosure-commitment"),
    signed_at: value("--signed-at") || undefined
  });
  process.stdout.write(`${JSON.stringify(signed, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
