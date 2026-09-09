#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const exists = (p) => fs.existsSync(path.join(root, p));

const failures = [];
const manifest = JSON.parse(read("conformance/manifest.json"));
const schema = JSON.parse(read("conformance/implementation-declaration.schema.json"));
const issueTemplate = read(".github/ISSUE_TEMPLATE/conformance-implementation.yml");

const protocols = manifest.protocols ?? [];
const protocolIds = protocols.map((entry) => entry.protocol);
const unique = new Set(protocolIds);

if (unique.size !== protocolIds.length) {
  failures.push("duplicate protocol identifier in conformance/manifest.json");
}

const schemaProtocols = schema?.properties?.protocol?.enum;
if (!Array.isArray(schemaProtocols)) {
  failures.push("implementation declaration schema must enumerate protocol identifiers");
} else {
  const manifestSorted = [...protocolIds].sort();
  const schemaSorted = [...schemaProtocols].sort();
  if (JSON.stringify(manifestSorted) !== JSON.stringify(schemaSorted)) {
    failures.push(`schema protocols do not match manifest protocols: manifest=${manifestSorted.join(",")} schema=${schemaSorted.join(",")}`);
  }
}

for (const entry of protocols) {
  if (!entry.name || !entry.protocol || !entry.status || !entry.scope) {
    failures.push(`incomplete protocol manifest entry: ${JSON.stringify(entry)}`);
    continue;
  }

  if (!issueTemplate.includes(entry.protocol)) {
    failures.push(`submission form does not expose protocol ${entry.protocol}`);
  }

  if (!entry.normativeDocument || !exists(entry.normativeDocument)) {
    failures.push(`missing normative document for ${entry.protocol}: ${entry.normativeDocument ?? "<unset>"}`);
  }

  const vectors = Array.isArray(entry.vectors) ? entry.vectors : [];
  if (vectors.length === 0) {
    failures.push(`protocol ${entry.protocol} has no published vector paths`);
  }
  for (const vectorPath of vectors) {
    if (!exists(vectorPath)) failures.push(`missing vector path for ${entry.protocol}: ${vectorPath}`);
  }

  for (const example of entry.independentExamples ?? []) {
    if (!exists(example)) failures.push(`missing independent example for ${entry.protocol}: ${example}`);
  }
}

const forbidden = "aml-conformance/canonical-json-1";
const filesThatMustNotUseDeprecatedProtocol = [
  "conformance/manifest.json",
  "conformance/implementation-declaration.schema.json",
  ".github/ISSUE_TEMPLATE/conformance-implementation.yml",
  ".github/workflows/conformance.yml",
  "conformance/SORTED_JSON_1.md",
  "conformance/README.md"
];

for (const file of filesThatMustNotUseDeprecatedProtocol) {
  if (exists(file) && read(file).includes(forbidden)) {
    failures.push(`deprecated overbroad protocol identifier remains in ${file}`);
  }
}

if (failures.length) {
  console.error(JSON.stringify({ valid: false, failures }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({
  valid: true,
  protocols: protocolIds,
  checkedProtocolCount: protocolIds.length
}, null, 2));
