// Run the shared trust-config conformance vectors against the JavaScript
// implementation. Output shape matches `python3 independent/python/trust_config.py
// conformance` and `aml-go-witness trust-conformance`.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  evaluateTrustConfig, initTrustState, trustConfigTrustsKey, trustConfigPinMatches, trustConfigRequiresSingleUse
} from "../../runtime/trustConfig.js";
import { openDurableConsumptionStore, consumptionKey } from "../../runtime/consumptionStore.js";
import { parseJsonWithoutDuplicateKeys } from "../../runtime/strictJson.js";

function applyBefore(action, stateDir) {
  const versions = path.join(stateDir, "versions");
  if (action.kind === "floor_future") {
    const file = path.join(versions, `v${String(action.version).padStart(12, "0")}.json`);
    const record = JSON.parse(fs.readFileSync(file, "utf8"));
    record.accepted_at = new Date(Date.now() + 86_400_000).toISOString();
    fs.writeFileSync(file, JSON.stringify(record));
  } else if (action.kind === "write_state_file") {
    fs.writeFileSync(path.join(versions, action.name), action.contents);
  } else if (action.kind === "remove_state_file") {
    fs.rmSync(path.join(versions, action.name));
  } else {
    throw new Error(`unknown before action ${action.kind}`);
  }
}

function project(decision, queries = []) {
  const trusted = decision.trusted === true;
  return {
    trusted, reasons: [...decision.reasons], version: decision.version ?? null,
    config_sha256: trusted ? decision.config_sha256 : null,
    effective: trusted ? JSON.parse(JSON.stringify(decision.effective)) : null,
    answers: queries.map(q => q.kind === "key" ? trustConfigTrustsKey(decision, q.keyid, q.role)
      : q.kind === "pin" ? trustConfigPinMatches(decision, q.field, q.actual)
        : q.kind === "single_use" ? trustConfigRequiresSingleUse(decision) : null)
  };
}

export function runCase(testCase, work) {
  const stateDir = path.join(work, "state");
  initTrustState(stateDir, { threshold: testCase.anchor.threshold, rootKeyids: testCase.anchor.keyids });
  let store = null;
  const out = [];
  for (const step of testCase.steps) {
    if (step.before) applyBefore(step.before, stateDir);
    if (step.consume) {
      store ??= openDurableConsumptionStore(path.join(work, "store"));
      const key = consumptionKey(step.consume.parts);
      out.push({ key, consumed: store.consume(key) });
      continue;
    }
    let envelope = step.envelope;
    if ("envelope_text" in step) {
      try { envelope = parseJsonWithoutDuplicateKeys(step.envelope_text); } catch { out.push({ parse_error: true }); continue; }
    }
    const onBeforePersist = "race_envelope" in step ? () => { evaluateTrustConfig(step.race_envelope, { stateDir }); } : null;
    out.push(project(evaluateTrustConfig(envelope, { stateDir, callerTime: step.caller_time ?? null, onBeforePersist }), step.queries));
  }
  return out;
}

export function runVectors(vectors) {
  return {
    implementation: "javascript",
    results: vectors.cases.map(testCase => {
      const work = fs.mkdtempSync(path.join(os.tmpdir(), "aml-tc-js-"));
      try { return { name: testCase.name, steps: runCase(testCase, work) }; } finally { fs.rmSync(work, { recursive: true, force: true }); }
    })
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const file = process.argv[2] || path.join(path.dirname(fileURLToPath(import.meta.url)), "vectors.json");
  console.log(JSON.stringify(runVectors(JSON.parse(fs.readFileSync(file, "utf8")))));
}
