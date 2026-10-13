import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

test("homepage boundary preview has one-choice semantics and a fresh module URL", () => {
  const page = readFileSync(new URL("../docs/index.html", import.meta.url), "utf8");
  const script = readFileSync(new URL("../docs/home-hero.js", import.meta.url), "utf8");
  const hash = createHash("sha256").update(script).digest("hex").slice(0, 12);
  assert.ok(page.includes(`home-hero.js?v=${hash}`));
  assert.match(page, /class="boundary-switch" role="radiogroup"/);
  assert.match(page, /data-boundary="action" aria-checked="true"/);
  assert.match(page, /data-boundary="interface" aria-checked="false" tabindex="-1"/);
  assert.match(page, /class="case-buttons action-case" role="radiogroup"/);
  assert.match(page, /data-action-destination="team" aria-checked="false" tabindex="-1"/);
  assert.match(page, /aria-label="Choose a declared restoration value"/);
  assert.match(page, /data-hero-value="5" aria-checked="false" tabindex="-1"/);
  assert.match(script, /button\.setAttribute\("aria-checked", String\(selected\)\)/);
  assert.match(script, /button\.tabIndex = selected \? 0 : -1/);
  assert.match(script, /\["ArrowRight", "ArrowDown"\]/);
  assert.match(script, /wireChoiceGroup\("\[data-hero-value\]"/);
});
