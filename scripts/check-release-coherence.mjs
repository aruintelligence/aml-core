#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const readText = (p) => fs.readFileSync(path.join(root, p), "utf8");
const readJson = (p) => JSON.parse(readText(p));

const contract = readJson("project-contract.json");
const readme = readText(contract.canonicalFiles.readme);
const changelog = readText(contract.canonicalFiles.changelog);

const failures = [];
const checks = [];
const check = (name, ok, detail) => {
  checks.push({ name, ok: Boolean(ok), detail });
  if (!ok) failures.push(`${name}: ${detail}`);
};

const { stableVersion, stableTag, previewVersion, previewTag, defaultChannel } = contract.release;

check("stable tag/version shape", stableTag === `v${stableVersion}`, `${stableTag} must equal v${stableVersion}`);
check("preview tag/version shape", previewTag === `v${previewVersion}`, `${previewTag} must equal v${previewVersion}`);
check("stable and preview differ", stableVersion !== previewVersion, "stable and preview versions must differ");
check("default channel is stable", defaultChannel === "stable", "defaultChannel must remain stable until an intentional release promotion changes it");

check(
  "README stable badge",
  readme.includes(`STABLE-v${stableVersion}`) && readme.includes(`/releases/tag/${stableTag}`),
  `README must link stable badge to ${stableTag}`
);
check(
  "README preview badge",
  readme.includes(`PREVIEW-v${previewVersion.replaceAll("-", "--")}`) && readme.includes(`/releases/tag/${previewTag}`),
  `README must link preview badge to ${previewTag}`
);
check(
  "README release status separates channels",
  readme.includes(`\`v${stableVersion}\` remains the stable package/CLI/capability contract`) &&
    readme.includes(`\`v${previewVersion}\` is the current GitHub prerelease snapshot`),
  "README must explicitly distinguish stable and preview channels"
);

const headings = [...changelog.matchAll(/^## \[([^\]]+)\]/gm)].map((m) => m[1]);
check("changelog contains stable release", headings.includes(stableVersion), `missing [${stableVersion}] heading`);
check("changelog contains preview release", headings.includes(previewVersion), `missing [${previewVersion}] heading`);

const firstPublished = headings.find((h) => h !== "Unreleased");
check(
  "changelog newest published entry matches preview",
  firstPublished === previewVersion,
  `first published changelog entry is ${firstPublished ?? "missing"}; expected ${previewVersion}`
);

const result = {
  valid: failures.length === 0,
  stable: { version: stableVersion, tag: stableTag },
  preview: { version: previewVersion, tag: previewTag },
  defaultChannel,
  checks: checks.length,
  failures
};

console.log(JSON.stringify(result, null, 2));
if (failures.length) process.exit(1);
