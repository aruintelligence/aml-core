import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const required = [
  "starters/plain-js/README.md",
  "starters/react/README.md",
  "starters/nextjs/README.md",
  "demos/interface-firewall/README.md",
  "demos/interface-firewall/before.aml",
  "demos/interface-firewall/after.aml",
  "demos/interface-firewall/context.json",
  "rfcs/README.md",
  "rfcs/0001-abstract-meaning-tree.md",
  "rfcs/0002-render-decision-protocol.md",
  "rfcs/0003-accountable-execution-receipt.md",
  "rfcs/0004-user-owned-policy-profiles.md",
  "SECURITY_THREAT_MODEL.md",
  "docs/CONFORMANCE_BADGE.md",
  "docs/WHY_TEAMS_USE_AML.md",
  "docs/VIEW_MEANING_BROWSER_EXTENSION.md",
  "docs/V1_4_ADOPTION_ROADMAP.md",
  "benchmarks/FIXTURES.md",
  "examples/github-actions/meaning-gate.yml",
  ".github/workflows/conformance.yml",
  "scripts/check-conformance.js",
  "ECOSYSTEM.md"
];

test("mainstream adoption surface remains present", () => {
  for (const path of required) {
    assert.equal(fs.existsSync(path), true, `missing adoption artifact: ${path}`);
  }
});

test("conformance manifest tracks current v1.3 contract", () => {
  const manifest = JSON.parse(fs.readFileSync("conformance/manifest.json", "utf8"));
  assert.equal(manifest.version, "1.3.0");
  const paths = new Set(manifest.fixtures.map((fixture) => fixture.path));
  assert.equal(paths.has("conformance/allow.aml"), true);
  assert.equal(paths.has("conformance/suppress.aml"), true);
});
