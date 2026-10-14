import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { inspectSnapshotEvidence, snapshotSelection, snapshotUrl } from "../docs/snapshot-binding.js";

const report = JSON.parse(readFileSync(new URL("../docs/action-snapshot-proof.json", import.meta.url), "utf8"));
const mutants = JSON.parse(readFileSync(new URL("../docs/action-dispatch-mutants.json", import.meta.url), "utf8"));
const page = readFileSync(new URL("../docs/snapshot-binding.html", import.meta.url), "utf8");
const script = readFileSync(new URL("../docs/snapshot-binding.js", import.meta.url));

test("the site pairs both current cases with the reintroduced two-read source mutation", () => {
  const changes = inspectSnapshotEvidence(report, mutants);
  assert.deepEqual(changes.map(item => [item.mode, item.mutant.accessor_reads,
    item.mutant.receipt_matches_callback]), [
    ["allow", 2, false], ["requires_approval", 2, false]
  ]);
  for (const mode of ["allow", "requires_approval"]) {
    const url = snapshotUrl("https://example.test/snapshot-binding.html", mode);
    assert.equal(snapshotSelection(new URL(url).search), mode);
    assert.equal(new URL(url).hash, "#comparison");
  }
  assert.equal(snapshotSelection("?mode=bogus"), "allow");
  assert.throws(() => snapshotUrl("https://example.test", "bogus"), RangeError);
});

test("the viewer rejects an invented receipt relationship and pairs its current script", () => {
  const falseReport = structuredClone(report);
  falseReport.rows[1].receipt_matches_callback = false;
  assert.throws(() => inspectSnapshotEvidence(falseReport, mutants), /comparison/);
  for (const required of ["action-snapshot-proof.json", "action-dispatch-mutants.json",
    "before-receipt", "after-callback", "no provider effect", "formal proof of production safety",
    "does not independently verify provenance"]) {
    assert.ok(page.toLowerCase().includes(required.toLowerCase()), required);
  }
  const version = createHash("sha256").update(script).digest("hex").slice(0, 12);
  assert.ok(page.includes(`src="snapshot-binding.js?v=${version}"`));
});
