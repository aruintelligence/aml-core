import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compileSource } from "../compiler/compiler.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function nodeMajor() {
  return Number(process.versions.node.split(".")[0]);
}

function packageMetadata() {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
}

function sampleSource() {
  return `transmission "doctor" {
  engram health {
    value: "AML installed package health check"
    purpose: "verify parser compiler and render-gate path"
    memory_role: "diagnostic"
    user_effect: "clarity"
    attention_cost: 1
    restoration_value: 2
  }
}`;
}

export function runAmlDoctor() {
  const checks = [];
  const pkg = packageMetadata();

  const supportedNode = nodeMajor() >= 18;
  checks.push({
    id: "node-runtime",
    ok: supportedNode,
    observed: process.version,
    required: pkg.engines?.node || ">=18.0.0"
  });

  let compileOk = false;
  let decisionCount = 0;
  let compileError = null;
  try {
    const result = compileSource(sampleSource(), { timestamp: "1970-01-01T00:00:00.000Z" });
    decisionCount = Array.isArray(result.renderDecisions) ? result.renderDecisions.length : 0;
    compileOk = Boolean(result.amt) && decisionCount > 0;
  } catch (error) {
    compileError = error?.message || String(error);
  }
  checks.push({
    id: "compile-and-govern",
    ok: compileOk,
    render_decisions: decisionCount,
    error: compileError
  });

  const indexPresent = fs.existsSync(path.join(ROOT, "index.js"));
  const cliPresent = fs.existsSync(path.join(ROOT, "bin", "aml.js"));
  checks.push({ id: "package-entrypoint", ok: indexPresent, path: "index.js" });
  checks.push({ id: "cli-entrypoint", ok: cliPresent, path: "bin/aml.js" });

  const healthy = checks.every(check => check.ok === true);
  return {
    protocol: "aml-doctor-report/1",
    healthy,
    package: pkg.name,
    package_version: pkg.version,
    node_version: process.version,
    platform: process.platform,
    arch: process.arch,
    checks,
    claim_boundary: "Local package/runtime health only; not independent validation, certification, standards status, or production suitability."
  };
}
