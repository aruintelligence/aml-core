// Generate conformance/policy-threshold/vectors.json: how a policy's
// `threshold` field resolves (protocol/policyThreshold.js). Each case is the
// raw JSON text of a policy, so "key absent", null, 2.0 and huge numbers are
// exercised exactly as every runtime parses them. Deterministic.
// Run: node conformance/policy-threshold/generate.mjs [--check]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolvePolicyThreshold } from "../../protocol/policyThreshold.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, "vectors.json");
const ok = threshold => ({ threshold, error: null });
const bad = { threshold: null, error: "invalid_threshold" };
const cases = [
  ["omitted", "{}", ok(1)],
  ["omitted_with_other_fields", "{\"trusted_fingerprints\":[]}", ok(1)],
  ["one", "{\"threshold\":1}", ok(1)],
  ["two", "{\"threshold\":2}", ok(2)],
  ["sixty_four", "{\"threshold\":64}", ok(64)],
  ["integer_valued_float_text", "{\"threshold\":2.0}", ok(2)],
  ["exponent_integer", "{\"threshold\":3e0}", ok(3)],
  ["max_safe_integer", "{\"threshold\":9007199254740991}", ok(9007199254740991)],
  ["zero", "{\"threshold\":0}", bad],
  ["negative_zero", "{\"threshold\":-0}", bad],
  ["negative", "{\"threshold\":-1}", bad],
  ["fraction", "{\"threshold\":1.5}", bad],
  ["unsafe_integer", "{\"threshold\":9007199254740992}", bad],
  ["huge", "{\"threshold\":1e300}", bad],
  ["string_number", "{\"threshold\":\"2\"}", bad],
  ["empty_string", "{\"threshold\":\"\"}", bad],
  ["boolean_true", "{\"threshold\":true}", bad],
  ["boolean_false", "{\"threshold\":false}", bad],
  ["null", "{\"threshold\":null}", bad],
  ["array", "{\"threshold\":[2]}", bad],
  ["object", "{\"threshold\":{\"k\":2}}", bad]
].map(([name, policy_json, expect]) => ({ name, policy_json, expect }));

const mismatches = cases.filter(c => JSON.stringify(resolvePolicyThreshold(JSON.parse(c.policy_json))) !== JSON.stringify(c.expect));
if (mismatches.length) { console.error(JSON.stringify(mismatches)); process.exit(1); }
const text = `${JSON.stringify({ type: "aml-policy-threshold-vectors/1",
  rule: "threshold omitted -> 1; positive safe integer -> itself; anything else -> invalid_threshold (threshold null), never 1",
  cases }, null, 1)}\n`;
if (process.argv.includes("--check")) {
  if (fs.readFileSync(OUT, "utf8") !== text) { console.error("conformance/policy-threshold/vectors.json is stale"); process.exit(1); }
  console.log(JSON.stringify({ ok: true, cases: cases.length }));
} else {
  fs.writeFileSync(OUT, text);
  console.log(JSON.stringify({ wrote: OUT, cases: cases.length }));
}
