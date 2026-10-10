import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { runEvidenceDrill } from "../runtime/evidenceDrill.js";
import { renderEvidenceDrillHtml } from "../runtime/evidenceDrillHtml.js";

const shares = [0, 1, 2].map(index => JSON.parse(fs.readFileSync(new URL(`../independent/vectors/shards-v1/share-${index}.json`, import.meta.url))));
const policy = JSON.parse(fs.readFileSync(new URL("../independent/vectors/archive-v1/trusted-policy.json", import.meta.url)));

test("offline view shows all verified paths and its scope", () => {
  const report = runEvidenceDrill(shares, policy);
  const html = renderEvidenceDrillHtml(report);
  assert.match(html, /All recovery paths open/);
  assert.equal((html.match(/Trusted handoff reconstructed/g) ?? []).length, 3);
  assert.match(html, new RegExp(report.policy_sha256));
  assert.match(html, /not an independent witness/);
  assert.doesNotMatch(html, /<script|https?:\/\//);
});

test("degraded view renders failure without implying readiness or injecting markup", () => {
  const report = runEvidenceDrill([null, shares[1], shares[2]], policy);
  report.pairs[0].reason = '<img src=x onerror="alert(1)">';
  const html = renderEvidenceDrillHtml(report);
  assert.match(html, /Recovery possible\. Repair needed/);
  assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
  assert.doesNotMatch(html, /<img/);
  assert.throws(() => renderEvidenceDrillHtml({ ...report, protocol: "unknown" }), /INVALID_REPORT/);
});
