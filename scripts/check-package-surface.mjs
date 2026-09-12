import fs from "node:fs";
import path from "node:path";

function fail(message) {
  console.error(message);
  process.exit(1);
}

const root = process.cwd();
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const contract = JSON.parse(fs.readFileSync(path.join(root, "package-surface.json"), "utf8"));
const project = JSON.parse(fs.readFileSync(path.join(root, "project-contract.json"), "utf8"));

if (contract.protocol !== "aml-package-surface/1") fail("Unsupported package surface protocol");
if (contract.package !== pkg.name) fail(`Package name drift: ${contract.package} != ${pkg.name}`);
if (contract.node !== pkg.engines?.node) fail("Node engine drift between package surface and package.json");
if (contract.stable_release.version !== project.release.stableVersion) fail("Stable version drift");
if (contract.stable_release.tag !== project.release.stableTag) fail("Stable tag drift");
if (contract.preview_release.version !== project.release.previewVersion) fail("Preview version drift");
if (contract.preview_release.tag !== project.release.previewTag) fail("Preview tag drift");

const rootExport = pkg.exports?.[contract.javascript.root_export];
const jsTarget = typeof rootExport === "string" ? rootExport : rootExport?.import ?? rootExport?.default;
const typeTarget = typeof rootExport === "object" ? rootExport?.types : pkg.types;
if (jsTarget !== contract.javascript.target) fail("JavaScript root export drift");
if (pkg.types !== contract.javascript.types.replace(/^\.\//, "")) fail("Top-level TypeScript declaration drift");
if (typeTarget !== contract.javascript.types) fail("Conditional TypeScript export drift");
for (const target of [contract.javascript.target, contract.javascript.types]) {
  const diskPath = path.join(root, target.replace(/^\.\//, ""));
  if (!fs.existsSync(diskPath)) fail(`Declared JavaScript package target is missing: ${target}`);
}

const declaredBins = contract.cli || {};
const packageBins = pkg.bin || {};
const declaredNames = Object.keys(declaredBins).sort();
const packageNames = Object.keys(packageBins).sort();
if (JSON.stringify(declaredNames) !== JSON.stringify(packageNames)) {
  fail(`CLI surface drift. contract=${declaredNames.join(",")} package=${packageNames.join(",")}`);
}

for (const name of declaredNames) {
  const declared = declaredBins[name];
  const actual = packageBins[name];
  if (declared !== actual) fail(`CLI target drift for ${name}: ${declared} != ${actual}`);
  const diskPath = path.join(root, declared.replace(/^\.\//, ""));
  if (!fs.existsSync(diskPath)) fail(`Declared CLI target is missing: ${name} -> ${declared}`);
}

const report = {
  protocol: "aml-package-surface-verification/1",
  valid: true,
  package: pkg.name,
  package_version: pkg.version,
  stable_release: contract.stable_release,
  preview_release: contract.preview_release,
  javascript_root: contract.javascript,
  typescript_declarations: contract.javascript.types,
  cli_count: declaredNames.length,
  cli_names: declaredNames,
  node: contract.node,
  claim_boundary: "Project-controlled package surface verification; not registry publication or independent adoption evidence."
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
