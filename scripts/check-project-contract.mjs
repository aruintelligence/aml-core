#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const readText = (p) => fs.readFileSync(path.join(root, p), "utf8");
const readJson = (p) => JSON.parse(readText(p));
const exists = (p) => fs.existsSync(path.join(root, p));

const failures = [];
const checks = [];

function check(name, condition, detail) {
  checks.push({ name, ok: Boolean(condition), detail });
  if (!condition) failures.push(`${name}: ${detail}`);
}

const contract = readJson("project-contract.json");
const pkg = readJson(contract.canonicalFiles.package);
const conformance = readJson(contract.canonicalFiles.conformanceManifest);
const citation = readText(contract.canonicalFiles.citation);
const claims = readText(contract.canonicalFiles.claims);
const readme = readText(contract.canonicalFiles.readme);

const stableVersion = contract.release.stableVersion;
const stableTag = contract.release.stableTag;

check(
  "contract schema",
  contract.schema === "aml-project-contract/1",
  `expected aml-project-contract/1, got ${contract.schema}`
);

for (const [key, file] of Object.entries(contract.canonicalFiles)) {
  check(`canonical file exists: ${key}`, exists(file), `${file} is missing`);
}

check(
  "package version matches stable version",
  pkg.version === stableVersion,
  `package.json=${pkg.version}; contract=${stableVersion}`
);

check(
  "conformance manifest version matches stable version",
  conformance.version === stableVersion,
  `conformance/manifest.json=${conformance.version}; contract=${stableVersion}`
);

const citationVersion = citation.match(/^version:\s*([^\s]+)\s*$/m)?.[1];
check(
  "citation version matches stable version",
  citationVersion === stableVersion,
  `CITATION.cff=${citationVersion ?? "missing"}; contract=${stableVersion}`
);

check(
  "citation preserves creator identity",
  citation.includes('family-names: "Read"') &&
    citation.includes('given-names: "Daniel Jacob"') &&
    citation.includes('name-suffix: "IV"'),
  "CITATION.cff must preserve Daniel Jacob Read IV as cited author"
);

check(
  "package repository matches canonical repository",
  pkg.repository?.url === `git+${contract.project.repository}.git`,
  `package repository=${pkg.repository?.url ?? "missing"}`
);

check(
  "package homepage matches canonical homepage",
  pkg.homepage === contract.project.homepage,
  `package homepage=${pkg.homepage ?? "missing"}`
);

check(
  "README stable release badge/tag matches contract",
  readme.includes(`STABLE-v${stableVersion}`) && readme.includes(`/releases/tag/${stableTag}`),
  `README must identify ${stableTag} as stable`
);

check(
  "README release status names stable version",
  readme.includes(`\`v${stableVersion}\` remains the stable package/CLI/capability contract`),
  `README release-status prose must name v${stableVersion}`
);

check(
  "README preserves prototype claim boundary",
  readme.includes("working research prototype"),
  "README must retain the working research prototype boundary"
);

const requiredNonClaims = [
  "it is a ratified global standard",
  "enterprises broadly use it in production",
  "its declared scores objectively measure human cognition or wellbeing",
  "an AML decision is automatically ethical, legally compliant, or factually correct"
];
for (const statement of requiredNonClaims) {
  check(
    `claims boundary preserved: ${statement}`,
    claims.includes(statement),
    `CLAIMS.md must retain non-claim: ${statement}`
  );
}

check(
  "contract and claims agree on standard status",
  contract.claimBoundary.ratifiedStandard === false,
  "ratifiedStandard must remain false until a real standards event changes it"
);

check(
  "contract and claims agree on broad adoption",
  contract.claimBoundary.broadProductionAdoptionClaim === false,
  "broadProductionAdoptionClaim must remain false without evidence"
);

for (const fixture of conformance.fixtures ?? []) {
  check(
    `conformance fixture exists: ${fixture.path}`,
    exists(fixture.path),
    `${fixture.path} referenced by conformance/manifest.json is missing`
  );
}

const fixturePaths = (conformance.fixtures ?? []).map((x) => x.path);
check(
  "conformance fixture paths are unique",
  new Set(fixturePaths).size === fixturePaths.length,
  "conformance manifest contains duplicate fixture paths"
);

const fixtureDomains = (conformance.fixtures ?? []).map((x) => x.domain);
check(
  "conformance fixture domains are unique",
  new Set(fixtureDomains).size === fixtureDomains.length,
  "conformance manifest contains duplicate fixture domains"
);

const result = {
  valid: failures.length === 0,
  schema: contract.schema,
  stableVersion,
  checks: checks.length,
  failures
};

console.log(JSON.stringify(result, null, 2));
if (failures.length) process.exit(1);
