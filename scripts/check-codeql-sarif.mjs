#!/usr/bin/env node
// Validate/report real CodeQL SARIF, not a replacement scanner or security proof.
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const CODEQL_SCOPE = {
  "javascript-typescript": ["boundary.mjs", "guarded-tool.mjs", "a2ui-function-gate.mjs",
    "one-shot-grants.mjs", "file-one-shot-grants.mjs", "file-dispatch-ledger.mjs",
    "signed-provider-status.mjs", "verify-provider-status.mjs", "provider-execution-state.mjs"],
  python: ["authorized_execution.py", "atomic-authorized-provider-fixture.py", "authorized-provider-fixture.py",
    "sqlite_path.py", "sqlite_execution_gate.py", "sqlite-provider-fixture.py", "sqlite-status-witness.py",
    "sqlite-epoch-coordinator.py", "python_boundary.py"]
};
const fail = message => { throw new Error(message); };
const object = (value, error) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(error);
  return value;
};
const text = (value, error) => { if (typeof value !== "string" || !value) fail(error); return value; };
const array = (owner, key, error, required = false) => {
  if (!Object.hasOwn(owner, key) && !required) return [];
  if (!Array.isArray(owner[key])) fail(error);
  return owner[key];
};
const levelOf = (value, fallback, error) => {
  const level = value === undefined ? fallback : value;
  if (!["error", "warning", "note", "none"].includes(level)) fail(error);
  return level;
};
const relativeUri = value => text(value, "invalid_codeql_artifact_uri").replaceAll("\\", "/").replace(/^\.\//, "");
function message(value) {
  object(value, "invalid_codeql_message");
  if (!(typeof value.text === "string" || typeof value.id === "string")) fail("invalid_codeql_message");
  for (const key of ["text", "id", "markdown"]) {
    if (Object.hasOwn(value, key) && typeof value[key] !== "string") fail("invalid_codeql_message");
  }
  if (array(value, "arguments", "invalid_codeql_message").some(arg => typeof arg !== "string")) fail("invalid_codeql_message");
  return value;
}
function locations(owner) {
  return array(owner, "locations", "invalid_codeql_locations").map(location => {
    object(location, "invalid_codeql_location");
    if (!Object.hasOwn(location, "physicalLocation")) return null; // Logical-only SARIF location.
    const physical = object(location.physicalLocation, "invalid_codeql_location");
    if (!Object.hasOwn(physical, "artifactLocation")) return null;
    const artifact = object(physical.artifactLocation, "invalid_codeql_location");
    return Object.hasOwn(artifact, "uri") ? relativeUri(artifact.uri) : null;
  }).filter(value => value !== null);
}
function descriptors(component, kind) {
  const list = array(component, kind, "invalid_codeql_descriptors"), ids = new Set();
  for (const descriptor of list) {
    object(descriptor, "invalid_codeql_descriptor"); text(descriptor.id, "invalid_codeql_descriptor");
    if (ids.has(descriptor.id)) fail("duplicate_codeql_descriptor");
    ids.add(descriptor.id);
    if (Object.hasOwn(descriptor, "defaultConfiguration")) {
      const config = object(descriptor.defaultConfiguration, "invalid_codeql_configuration");
      levelOf(config.level, "warning", "invalid_codeql_configuration");
      if (Object.hasOwn(config, "enabled") && typeof config.enabled !== "boolean") fail("invalid_codeql_configuration");
    }
  }
  return list;
}
// Resolve within components, never flatten colliding IDs across packs. Index/id
// disagreement or unsupported/unresolved references fail rather than guess severity.
function resolveDescriptor(reference, components, kind, legacyId) {
  if (reference === undefined) reference = { id: legacyId };
  object(reference, "invalid_codeql_descriptor_reference");
  if (Object.hasOwn(reference, "id")) text(reference.id, "invalid_codeql_descriptor_reference");
  if (Object.hasOwn(reference, "index") && (!Number.isInteger(reference.index) || reference.index < -1)) fail("invalid_codeql_descriptor_reference");
  if (reference.id === undefined && !(reference.index >= 0)) fail("unsupported_codeql_descriptor_reference");
  let selected = components;
  if (Object.hasOwn(reference, "toolComponent")) {
    const ref = object(reference.toolComponent, "invalid_codeql_component_reference");
    if (Object.hasOwn(ref, "index")) {
      if (!Number.isInteger(ref.index) || ref.index < -1 || ref.index >= components.length - 1) fail("invalid_codeql_component_reference");
      selected = [components[ref.index + 1]]; // -1 denotes driver, others index extensions.
    } else {
      selected = components.filter(c => (ref.name === undefined || c.name === ref.name) && (ref.guid === undefined || c.guid === ref.guid));
      if (ref.name === undefined && ref.guid === undefined) fail("invalid_codeql_component_reference");
    }
    if (selected.length !== 1 || (ref.name !== undefined && ref.name !== selected[0].name) ||
        (ref.guid !== undefined && ref.guid !== selected[0].guid)) fail("invalid_codeql_component_reference");
  } else if (reference.index >= 0) selected = [components[0]]; // SARIF default component is driver.
  const found = selected.flatMap(c => c[kind].filter((d, i) =>
    (reference.index === undefined || reference.index === -1 || i === reference.index) &&
    (reference.id === undefined || d.id === reference.id) && (reference.guid === undefined || d.guid === reference.guid)));
  if (found.length !== 1 || (legacyId !== undefined && found[0].id !== legacyId)) fail("unresolved_codeql_descriptor_reference");
  return found[0];
}
// Narrow, versioned policy over observed CodeQL IDs, NOT "every warning fails".
// OASIS permits warning/default-warning parser diagnostics; actual historical
// CodeQL emitted js/parse-error as well as js/diagnostics/extraction-errors.
// Python's upstream ExtractionWarnings.ql specifically reports SyntaxError,
// not arbitrary benign warnings. Our full-source evidence policy rejects it too.
const EXTRACTION_FAILURE_IDS = new Set(["js/parse-error", "js/diagnostics/extraction-errors", "py/diagnostics/extraction-warnings"]);
const extractionFailure = id => EXTRACTION_FAILURE_IDS.has(id);
// The workflow pins codeql-action 33d7b85 (v4.39.3) with tools: linked, whose
// bundle is CLI 2.27.4. A different producer version is not the reviewed profile.
export const EXPECTED_CODEQL_CLI_VERSION = "2.27.4";
// Pinned Action analyze.ts adds --sarif-run-property=incrementalMode=<modes> ONLY
// for diff-informed and/or overlay analysis; full analysis omits the property.
// Absent therefore means full; any present value other than "none" is partial/unknown.
// Diff-informed runs also load this extension pack, so its presence rejects too.
const DIFF_RANGE_EXTENSION_PACK = "codeql-action/pr-diff-range";
// Public, non-sensitive enum reason codes (no paths, messages, or snippets).
export const QUALITY_REASON_CODES = Object.freeze(["incomplete_or_unknown_codeql_scope", "diff_informed_codeql_extension",
  "unexpected_codeql_cli_version", "extraction_failure_diagnostic", "error_level_notification", "required_artifacts_missing"]);
export const VALIDATOR_ERROR_CODES = Object.freeze(["missing_codeql_sarif_runs", "unsupported_external_codeql_report", "invalid_codeql_run",
  "not_codeql_analysis", "missing_codeql_version", "unsuccessful_codeql_invocation", "missing_codeql_results", "invalid_codeql_extensions",
  "invalid_codeql_component", "missing_expected_language_rules", "missing_security_extended_suite", "invalid_codeql_artifacts",
  "invalid_codeql_artifact", "invalid_codeql_artifact_uri", "invalid_codeql_configuration", "unsupported_codeql_configuration_override",
  "invalid_codeql_notifications", "invalid_codeql_notification", "invalid_codeql_notification_level", "invalid_codeql_message",
  "invalid_codeql_locations", "invalid_codeql_location", "invalid_codeql_descriptors", "invalid_codeql_descriptor",
  "duplicate_codeql_descriptor", "invalid_codeql_descriptor_reference", "unsupported_codeql_descriptor_reference",
  "invalid_codeql_component_reference", "unresolved_codeql_descriptor_reference", "invalid_codeql_result", "unknown_codeql_result_rule",
  "invalid_codeql_result_level", "invalid_codeql_suppressions", "invalid_codeql_external_properties", "unsupported_codeql_language",
  "expected_exactly_one_language_sarif", "usage_directory_language_required"]);

export function summarizeCodeql(sarif, language) {
  if (!Object.hasOwn(CODEQL_SCOPE, language)) fail("unsupported_codeql_language");
  object(sarif, "missing_codeql_sarif_runs");
  if (sarif.version !== "2.1.0" || !Array.isArray(sarif.runs) || sarif.runs.length < 1) fail("missing_codeql_sarif_runs");
  if (array(sarif, "inlineExternalProperties", "invalid_codeql_external_properties").length) fail("unsupported_external_codeql_report");
  const prefix = language === "python" ? "py/" : "js/";
  const findings = [], diagnosticErrors = [], notifications = [], versions = new Set(), artifacts = new Set(), scanModes = [];
  let ruleCount = 0;
  for (const run of sarif.runs) {
    object(run, "invalid_codeql_run");
    const tool = object(run.tool, "not_codeql_analysis"); object(tool.driver, "not_codeql_analysis");
    if (tool.driver.name !== "CodeQL") fail("not_codeql_analysis");
    for (const key of ["semanticVersion", "version"]) {
      if (Object.hasOwn(tool.driver, key)) text(tool.driver[key], "missing_codeql_version");
    }
    const version = tool.driver.semanticVersion ?? tool.driver.version;
    text(version, "missing_codeql_version"); versions.add(version);
    if (version !== EXPECTED_CODEQL_CLI_VERSION) diagnosticErrors.push({ id: "unexpected_codeql_cli_version", level: "error", files: [],
      message: { text: "Expected CodeQL CLI " + EXPECTED_CODEQL_CLI_VERSION } });
    if (Object.hasOwn(run, "externalPropertyFileReferences")) fail("unsupported_external_codeql_report");
    const invocations = array(run, "invocations", "unsuccessful_codeql_invocation", true);
    if (!invocations.length || invocations.some(i => i === null || typeof i !== "object" || Array.isArray(i) || i.executionSuccessful !== true)) fail("unsuccessful_codeql_invocation");
    const results = array(run, "results", "missing_codeql_results", true);
    const components = [tool.driver, ...array(tool, "extensions", "invalid_codeql_extensions")].map(component => {
      object(component, "invalid_codeql_component"); text(component.name, "invalid_codeql_component");
      return { ...component, rules: descriptors(component, "rules"), notifications: descriptors(component, "notifications") };
    });
    if (components.some(c => c.name === DIFF_RANGE_EXTENSION_PACK)) diagnosticErrors.push({ id: "diff_informed_codeql_extension",
      level: "error", files: [], message: { text: "Diff-range extension pack indicates PR-diff-only analysis" } });
    const languageRules = components.flatMap(c => c.rules).filter(rule => rule.id.startsWith(prefix));
    if (!languageRules.length) fail("missing_expected_language_rules"); ruleCount += languageRules.length;
    const properties = object(run.properties, "missing_security_extended_suite");
    const summary = object(properties.codeqlConfigSummary, "missing_security_extended_suite");
    const queries = array(summary, "queries", "missing_security_extended_suite", true);
    if (!queries.every(query => query && typeof query === "object" && !Array.isArray(query) && typeof query.uses === "string") ||
        !queries.some(query => query.uses === "security-extended")) fail("missing_security_extended_suite");
    for (const artifact of array(run, "artifacts", "invalid_codeql_artifacts", true)) {
      object(artifact, "invalid_codeql_artifact");
      const location = object(artifact.location, "invalid_codeql_artifact"); artifacts.add(relativeUri(location.uri));
    }
    for (const invocation of invocations) {
      if (Object.hasOwn(invocation, "exitCode") && (!Number.isInteger(invocation.exitCode) || invocation.exitCode !== 0)) fail("unsuccessful_codeql_invocation");
      for (const key of ["exitSignalName", "exitSignalNumber", "processStartFailureMessage"]) {
        if (Object.hasOwn(invocation, key)) fail("unsuccessful_codeql_invocation");
      }
      // This self-contained profile does not interpret severity policy/override
      // chains. Reject rather than misattribute or hide findings under overrides.
      for (const key of ["ruleConfigurationOverrides", "notificationConfigurationOverrides"]) {
        if (array(invocation, key, "invalid_codeql_configuration").length) fail("unsupported_codeql_configuration_override");
      }
      const execution = array(invocation, "toolExecutionNotifications", "invalid_codeql_notifications");
      const configuration = array(invocation, "toolConfigurationNotifications", "invalid_codeql_notifications");
      for (const notification of [...execution, ...configuration]) {
        object(notification, "invalid_codeql_notification"); message(notification.message);
        const descriptor = notification.descriptor === undefined ? undefined : resolveDescriptor(notification.descriptor, components, "notifications");
        const level = levelOf(notification.level, descriptor?.defaultConfiguration?.level ?? "warning", "invalid_codeql_notification_level");
        const item = { id: descriptor?.id ?? "unidentified_diagnostic", level,
          message: notification.message, files: locations(notification) };
        notifications.push(item);
        if (level === "error" || extractionFailure(item.id)) diagnosticErrors.push(item);
      }
    }
    if (array(run, "policies", "invalid_codeql_configuration").length) fail("unsupported_codeql_configuration_override");
    for (const result of results) {
      object(result, "invalid_codeql_result"); message(result.message);
      text(result.ruleId, "unknown_codeql_result_rule");
      const reference = Object.hasOwn(result, "rule") ? result.rule : { id: result.ruleId, ...(Object.hasOwn(result, "ruleIndex") ? { index: result.ruleIndex } : {}) };
      const rule = resolveDescriptor(reference, components, "rules", result.ruleId);
      if (Object.hasOwn(result, "ruleIndex") && result.ruleIndex !== (result.rule?.index ?? reference.index)) fail("invalid_codeql_descriptor_reference");
      const level = levelOf(result.level, rule.defaultConfiguration?.level ?? "warning", "invalid_codeql_result_level");
      const suppressions = array(result, "suppressions", "invalid_codeql_suppressions");
      for (const suppression of suppressions) {
        object(suppression, "invalid_codeql_suppressions");
        if (!["external", "inSource"].includes(suppression.kind)) fail("invalid_codeql_suppressions");
      }
      findings.push({ rule_id: result.ruleId, level,
        security_severity: rule.properties?.["security-severity"] ?? null,
        suppressions_present: suppressions.length > 0, files: locations(result) });
    }
    // Do not discard historical findings merely because scope is partial/unknown.
    // This metadata is asserted by the producer, not a cryptographic attestation.
    const modePresent = Object.hasOwn(properties, "incrementalMode"), mode = properties.incrementalMode;
    scanModes.push(!modePresent ? "full_action_default" : typeof mode === "string" ? mode : "unknown");
    if (modePresent && mode !== "none") diagnosticErrors.push({ id: "incomplete_or_unknown_codeql_scope", level: "error", files: [],
      message: { text: "Expected full analysis (incrementalMode absent or none); received " + String(mode) } });
  }
  const missing = CODEQL_SCOPE[language].map(name => "pilots/action-boundary/" + name).filter(name => !artifacts.has(name));
  // Artifact presence is inventory, not proof of extraction or trusted provenance.
  const qualityValid = diagnosticErrors.length === 0 && missing.length === 0;
  const reasons = new Set(diagnosticErrors.map(item => QUALITY_REASON_CODES.includes(item.id) ? item.id
    : extractionFailure(item.id) ? "extraction_failure_diagnostic" : "error_level_notification"));
  if (missing.length) reasons.add("required_artifacts_missing");
  return { protocol: "aml-codeql-sarif-review/1", language, codeql_versions: [...versions], scan_modes: scanModes,
    security_extended: true, language_rule_count: ruleCount, findings_count: findings.length,
    findings_by_level: Object.fromEntries(["error", "warning", "note", "none"].map(level => [level, findings.filter(f => f.level === level).length])),
    findings, notifications, extraction_or_configuration_errors: diagnosticErrors, required_artifacts_missing: missing,
    quality_reason_codes: QUALITY_REASON_CODES.filter(code => reasons.has(code)), analysis_quality_valid: qualityValid, security_clean: qualityValid && findings.length === 0,
    claim_boundary: "Untrusted CodeQL metadata/findings format review, not scanner authentication, extraction-completeness proof, vulnerability absence, or universal authorization non-bypass. Findings require human triage; none are silently suppressed." };
}

export function reviewDirectory(directory, language) {
  const files = fs.readdirSync(directory).filter(file => file.endsWith(".sarif")).sort();
  if (files.length !== 1) fail("expected_exactly_one_language_sarif");
  return summarizeCodeql(JSON.parse(fs.readFileSync(path.join(directory, files[0]), "utf8")), language);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 4) fail("usage_directory_language_required");
    const report = reviewDirectory(process.argv[2], process.argv[3]);
    console.log(JSON.stringify(report, null, 2));
    if (!report.analysis_quality_valid) process.exitCode = 1;
  } catch (error) {
    console.error(JSON.stringify({ protocol: "aml-codeql-sarif-review/1", analysis_quality_valid: false, error: error.message }));
    process.exitCode = 1;
  }
}
