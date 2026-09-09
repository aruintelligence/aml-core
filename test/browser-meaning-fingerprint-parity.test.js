import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { meaningFingerprint } from "../index.js";
import { meaningFingerprintBrowser, compareMeaningFingerprintsBrowser } from "../docs/aml-meaning-fingerprint.js";

for (const file of [
  "examples/simple.aml",
  "examples/ai_assistant_response.aml",
  "examples/accessibility_first.aml",
  "examples/ethical_ads.aml",
  "examples/focus_mode.aml",
  "examples/social_feed.aml",
  "conformance/allow.aml",
  "conformance/suppress.aml"
]) {
  test(`browser Meaning Fingerprint matches Node: ${file}`, async () => {
    const source = fs.readFileSync(file, "utf8");
    const node = meaningFingerprint(source);
    const browser = await meaningFingerprintBrowser(source);
    assert.deepEqual(browser, node);
  });
}

test("browser equivalence ignores comments/whitespace and detects declared meaning changes", async () => {
  const left = `transmission "demo" {
    engram card {
      purpose: "Explain clearly"
      attention_cost: 2
      restoration_value: 5
    }
  }`;
  const same = `// comment only
  transmission "demo" {

    engram card {
      purpose: "Explain clearly"
      attention_cost: 2
      restoration_value: 5
    }
  }`;
  const changed = left.replace("Explain clearly", "Create urgency");

  assert.equal((await compareMeaningFingerprintsBrowser(left, same)).equivalent, true);
  assert.equal((await compareMeaningFingerprintsBrowser(left, changed)).equivalent, false);
});
