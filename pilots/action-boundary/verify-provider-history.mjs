#!/usr/bin/env node
// A caller-retained evidence set is required to detect conflicting snapshots.
import fs from "node:fs";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { verifyProviderHistory } from "./verify-provider-status.mjs";

const [publicKeyFile, operationId, requestSha256, destination] = process.argv.slice(2);
let result = "REJECTED";
try {
  const raw = fs.readFileSync(0, "utf8");
  if (Buffer.byteLength(raw, "utf8") > 262144) throw Error("oversized_history");
  const input = JSON.parse(raw);
  if (raw !== canonicalJSONStringify(input) || !input ||
      Object.keys(input).sort().join("|") !== "challenges|envelopes") {
    throw Error("noncanonical_history");
  }
  result = verifyProviderHistory(input.envelopes, {
    challenges: input.challenges, publicKey: fs.readFileSync(publicKeyFile),
    operationId, requestSha256, destination
  });
} catch { result = "REJECTED"; }
console.log(JSON.stringify({ protocol: "aml-fixture-provider-history-verification/1",
  result, independent_confirmation: false }));
if (result === "REJECTED") process.exitCode = 2;
