#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

export const hashBytes = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
export const hashJSON = value => hashBytes(Buffer.from(canonicalJSONStringify(value), "utf8"));

export function verifyObservation(record, screenshot, corpusBytes) {
  const { receipt_sha256, ...body } = record;
  assert.equal(record.protocol, "aml-action-browser-observation/1");
  assert.equal(record.source_commit, "c3d9fc70489ba1d57d30450817a7a8c3d820cb05");
  assert.equal(record.public_url, "https://aruintelligence.github.io/aml-core/action-browser-matrix.html");
  assert.equal(record.screenshot_file, "aml-action-browser-100.jpg");
  assert.equal(record.screenshot_sha256, hashBytes(screenshot));
  assert.equal(record.result.protocol, "aml-action-browser-challenge-result/1");
  assert.equal(record.result.case_count, 100);
  assert.equal(record.result.passed, 100);
  assert.deepEqual(record.result.failed_fields, []);
  assert.equal(record.result.cases_sha256, hashBytes(corpusBytes));
  assert.equal(record.result.implementation, "project-maintained browser WebCrypto");
  assert.match(record.result.browser, /Chrome\/154\.0\.0\.0/);
  assert.equal(receipt_sha256, hashJSON(body));
  return { receipt_sha256, screenshot_sha256: record.screenshot_sha256,
    cases_sha256: record.result.cases_sha256, passed: record.result.passed };
}

if (process.argv[1]?.endsWith("verify-action-browser-observation.mjs")) {
  const recordUrl = new URL("../docs/evidence/aml-action-browser-100.json", import.meta.url);
  const record = JSON.parse(fs.readFileSync(recordUrl, "utf8"));
  const screenshot = fs.readFileSync(new URL("../docs/evidence/aml-action-browser-100.jpg", import.meta.url));
  const corpus = fs.readFileSync(new URL("../conformance/action-boundary-expanded-cases.json", import.meta.url));
  if (process.argv[2] === "--seal") {
    const { receipt_sha256, ...body } = record;
    fs.writeFileSync(recordUrl, JSON.stringify({ ...body, receipt_sha256: hashJSON(body) }, null, 2) + "\n");
  } else if (process.argv[2] !== undefined) throw new Error("Use no option or --seal");
  const sealed = JSON.parse(fs.readFileSync(recordUrl, "utf8"));
  console.log(JSON.stringify(verifyObservation(sealed, screenshot, corpus), null, 2));
}
