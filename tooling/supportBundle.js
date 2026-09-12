import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { runAmlDoctor } from "./doctor.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const CONTRACT_FILES = [
  "project-contract.json",
  "package-surface.json",
  "api-stability.json",
  "api-surface.snapshot.json",
  "upgrade-contract.json",
  "security-baseline.json",
  "external-evidence.json"
];

function fileEvidence(relativePath) {
  const absolutePath = path.join(ROOT, relativePath);
  if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
    return { path: relativePath, present: false, size: 0, sha256: null };
  }
  const bytes = fs.readFileSync(absolutePath);
  return {
    path: relativePath,
    present: true,
    size: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex")
  };
}

export function createAmlSupportBundle() {
  const doctor = runAmlDoctor();
  const contracts = CONTRACT_FILES.map(fileEvidence);
  const contractsPresent = contracts.every(item => item.present);
  const material = contracts.map(item => `${item.path}\t${item.present}\t${item.size}\t${item.sha256 || "-"}`).join("\n") + "\n";
  const contractSetSha256 = crypto.createHash("sha256").update(material).digest("hex");
  return {
    protocol: "aml-support-bundle/1",
    healthy: Boolean(doctor.healthy && contractsPresent),
    package: doctor.package,
    package_version: doctor.package_version,
    node_version: doctor.node_version,
    platform: doctor.platform,
    arch: doctor.arch,
    doctor,
    contracts,
    contract_set_sha256: contractSetSha256,
    generated_at: null,
    privacy: {
      includes_file_contents: false,
      includes_environment_variables: false,
      includes_credentials: false,
      includes_private_keys: false
    },
    claim_boundary: "Local support and diagnostics evidence only. The bundle hashes declared public contracts but does not contain their contents, secrets, independent validation, certification, or proof of registry publication."
  };
}

export { CONTRACT_FILES as AML_SUPPORT_CONTRACT_FILES };
