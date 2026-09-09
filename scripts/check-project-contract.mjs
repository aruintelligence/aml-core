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
const claimsLedger = readJson(contract.canonicalFiles.claimsLedger);
const citation = readText(contract.canonicalFiles.citation);
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
  "claims ledger schema",
  claimsLedger.type === "aml-claims-ledger/1",
  `unexpected claims ledger type ${claimsLedger.type}`
);

const claimIds = (claimsLedger.claims ?? []).map((claim) => claim.id);
check(
  "claim IDs are unique",
  new Set(claimIds).size === claimIds.length,
  "claims.json contains duplicate claim IDs"
);

const allowedStatuses = new Set(claimsLedger.status_labels ?? []);
for (const claim of claimsLedger.claims ?? []) {
  check(
    `claim status allowed: ${claim.id}`,
    allowedStatuses.has(claim.status),
    `${claim.id} uses undeclared status ${claim.status}`
  );

  if (claim.status === "SHIPPED") {
    check(
      `SHIPPED claim has evidence: ${claim.id}`,
      Array.isArray(claim.evidence) && claim.evidence.length > 0,
      `${claim.id} is SHIPPED without evidence`
    );
    for (const evidence of claim.evidence ?? []) {
      check(
        `claim evidence exists: ${claim.id} -> ${evidence}`,
        exists(evidence),
        `${claim.id} references missing evidence ${evidence}`
      );
    }
  }
}

const nonClaims = new Set(claimsLedger.non_claims ?? []);
const requiredNonClaims = [
  "ratified global standard",
  "broad enterprise production adoption",
  "objective measurement of human cognition",
  "guaranteed ethical or legal correctness"
];
for (const statement of requiredNonClaims) {
  check(
    `machine claim boundary preserved: ${statement}`,
    nonClaims.has(statement),
    `claims.json must retain non-claim: ${statement}`
  );
}

check(
  "contract and claims agree on standard status",
  contract.claimBoundary.ratifiedStandard === false && nonClaims.has("ratified global standard"),
  "project contract and claims ledger disagree on standards status"
);

check(
  "contract and claims agree on broad adoption",
  contract.claimBoundary.broadProductionAdoptionClaim === false && nonClaims.has("broad enterprise production adoption"),
  "project contract and claims ledger disagree on broad production adoption"
);

check(
  "contract and claims agree on cognition measurement",
  contract.claimBoundary.objectiveHumanCognitionMeasurementClaim === false && nonClaims.has("objective measurement of human cognition"),
  "project contract and claims ledger disagree on cognition measurement"
);

check(
  "contract and claims agree on ethics/compliance guarantee",
  contract.claimBoundary.automaticEthicsOrComplianceClaim === false && nonClaims.has("guaranteed ethical or legal correctness"),
  "project contract and claims ledger disagree on ethics/compliance guarantee"
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
