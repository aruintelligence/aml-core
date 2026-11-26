// Generate conformance/quorum-safety/vectors.json: every k-of-n with
// 1 <= k <= n <= 16, the boundary sizes 17..64 at k = ceil((n+2)/2) - 1 and
// k = ceil((n+2)/2), and malformed inputs. Expectations are computed here
// from the arithmetic, independently of protocol/quorumSafety.js, and then
// checked against it. Deterministic. Run: node conformance/quorum-safety/generate.mjs [--check]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateQuorumSafety } from "../../protocol/quorumSafety.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, "vectors.json");

function expected(k, n) {
  const intersection = 2 * k - n;
  const t = { quorum_intersection: intersection, safety_fault_tolerance: intersection - 1, liveness_fault_tolerance: n - k };
  if (intersection <= 0) return { valid: false, reason: "quorums_may_not_intersect", ...t };
  if (intersection - 1 < 1) return { valid: false, reason: "zero_fault_tolerance", ...t };
  return { valid: true, reason: null, ...t };
}
const cases = [];
for (let n = 1; n <= 16; n += 1) for (let k = 1; k <= n; k += 1) cases.push({ threshold: k, witness_count: n, expect: expected(k, n) });
for (let n = 17; n <= 64; n += 1) {
  const minSafe = Math.ceil((n + 2) / 2);
  for (const k of [minSafe - 1, minSafe, n]) cases.push({ threshold: k, witness_count: n, expect: expected(k, n) });
}
const bad = (threshold, witness_count, reason) => cases.push({ threshold, witness_count, expect: { valid: false, reason } });
bad(0, 4, "threshold_out_of_range");
bad(-1, 4, "threshold_out_of_range");
bad(5, 4, "threshold_out_of_range");
bad(3, 0, "witness_count_out_of_range");
bad(33, 65, "witness_count_out_of_range");
bad(3, -4, "witness_count_out_of_range");
bad(2.5, 4, "threshold_not_integer");
bad("3", 4, "threshold_not_integer");
bad(true, 4, "threshold_not_integer");
bad(null, 4, "threshold_not_integer");
bad(3, 4.5, "witness_count_not_integer");
bad(3, "4", "witness_count_not_integer");
bad(3, null, "witness_count_not_integer");
bad(1e300, 4, "threshold_not_integer");

const vectors = {
  type: "aml-quorum-safety-vectors/1",
  rule: "integers 1 <= k <= n <= 64 and safety_fault_tolerance = 2k - n - 1 >= 1",
  cases
};
// Self-check against the implementation (only the expectation fields).
const mismatches = cases.filter(c => {
  const got = evaluateQuorumSafety(c.threshold, c.witness_count);
  return Object.entries(c.expect).some(([k, v]) => got[k] !== v);
});
if (mismatches.length) { console.error(JSON.stringify(mismatches.slice(0, 5))); process.exit(1); }
const text = `${JSON.stringify(vectors, null, 1)}\n`;
if (process.argv.includes("--check")) {
  if (fs.readFileSync(OUT, "utf8") !== text) { console.error("conformance/quorum-safety/vectors.json is stale"); process.exit(1); }
  console.log(JSON.stringify({ ok: true, cases: cases.length }));
} else {
  fs.writeFileSync(OUT, text);
  console.log(JSON.stringify({ wrote: OUT, cases: cases.length, accepted: cases.filter(c => c.expect.valid).length }));
}
