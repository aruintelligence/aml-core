import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hashJSON, verifyObservation } from "../scripts/verify-action-browser-observation.mjs";

const record = JSON.parse(readFileSync(new URL("../docs/evidence/aml-action-browser-100.json", import.meta.url)));
const screenshot = readFileSync(new URL("../docs/evidence/aml-action-browser-100.jpg", import.meta.url));
const cases = readFileSync(new URL("../conformance/action-boundary-expanded-cases.json", import.meta.url));

test("observed Chrome result binds exact screenshot, corpus and source checkpoint", () => {
  assert.equal(verifyObservation(record, screenshot, cases).passed, 100);
});

test("a changed screenshot or outcome fails even if the observation is rehashed", () => {
  const alteredScreenshot = Buffer.from(screenshot);
  alteredScreenshot[100] ^= 1;
  assert.throws(() => verifyObservation(record, alteredScreenshot, cases));
  const altered = structuredClone(record);
  altered.result.passed = 99;
  const { receipt_sha256, ...body } = altered;
  altered.receipt_sha256 = hashJSON(body);
  assert.throws(() => verifyObservation(altered, screenshot, cases));
});
