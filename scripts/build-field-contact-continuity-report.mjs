import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { evaluateContactContinuity } from "../pilots/field-contact-continuity.mjs";

const root = new URL("../", import.meta.url);
const prefix = "experiments/2026-10-11/portland-contact-continuity/";
const observation = JSON.parse(readFileSync(new URL(prefix + "observations.json", root), "utf8"));
const labels = JSON.parse(readFileSync(new URL(prefix + "labels.json", root), "utf8"));
for (const screen of observation.screens) {
  const digest = createHash("sha256").update(readFileSync(new URL(screen.screenshot, root))).digest("hex");
  if (digest !== screen.screenshot_sha256) throw new Error(`Screenshot changed: ${screen.id}`);
}
const report = { protocol: "aml-field-contact-continuity-report/1", site_url: observation.site_url,
  evidence: { screenshots: observation.screens.map(({ id, captured_at, scroll_y, screenshot, screenshot_sha256, visible, boxes }) =>
    ({ id, captured_at, scroll_y, screenshot, screenshot_sha256, visible, boxes })),
    observed_elements: observation.elements, viewport: observation.browser_viewport,
    screenshot_pixels: observation.screenshot_pixels },
  label_source: labels.source, rule: labels.rule,
  required_channels: labels.required_visible_channels_per_observed_screen,
  candidate: evaluateContactContinuity(observation, labels),
  over_suppression_probe: evaluateContactContinuity(observation, labels, { adversarial: true }),
  limits: labels.limits };
const output = JSON.stringify(report, null, 2) + "\n";
const path = new URL("docs/field-contact-continuity-report.json", root);
if (process.argv.includes("--check")) {
  if (readFileSync(path, "utf8") !== output) throw new Error("Published field report is stale");
  console.log("Field report and both screenshot hashes match.");
} else writeFileSync(path, output);
