#!/usr/bin/env node

import fs from "node:fs";
import { signGovernanceStreamTranscript } from "../protocol/governanceTranscriptSignature.js";

function value(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? fallback : fallback;
}

const transcriptPath = process.argv[2];
const keyPath = value("--key");
const keyId = value("--key-id");
const signer = value("--signer");
const scope = value("--scope", "governance-transcript-integrity");
const signedAt = value("--signed-at");

if (!transcriptPath || !keyPath) {
  console.error("Usage: aml-governance-transcript-sign <transcript.json> --key <ed25519-private.pem> [--key-id id] [--signer name] [--scope scope] [--signed-at timestamp]");
  process.exit(1);
}

try {
  const transcript = JSON.parse(fs.readFileSync(transcriptPath, "utf8"));
  const privateKeyPem = fs.readFileSync(keyPath, "utf8");
  const signed = signGovernanceStreamTranscript(transcript, privateKeyPem, {
    key_id: keyId || undefined,
    signer: signer || undefined,
    scope,
    signed_at: signedAt || undefined
  });
  process.stdout.write(`${JSON.stringify(signed, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exitCode = 1;
}
