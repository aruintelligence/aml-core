#!/usr/bin/env node
import { pathToFileURL } from "node:url";

// Pinned init ORs input debug with core.isDebug(); upload:never does not
// disable its separate debug post-action. Also reject debug-SARIF selectors;
// this is not a claim that every selector reaches an uploader in this workflow.
const disabledDebug = new Set(["RUNNER_DEBUG", "ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG",
  "INPUT_DEBUG", "CODEQL_ACTION_DEBUG_COMBINED_SARIF", "CODEQL_ACTION_JAVA_NETWORK_DEBUGGING"]);
const allowedCodeql = new Map([
  ["CODEQL_ACTION_DIFF_INFORMED_QUERIES", "false"],
  ["CODEQL_ACTION_OVERLAY_ANALYSIS", "false"],
  ["CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES", "true"]
]);
export function assertNoCodeqlDebug(env = process.env) {
  for (const [name, value] of Object.entries(env)) {
    if (disabledDebug.has(name)) {
      if (typeof value !== "string" || !["", "0", "false"].includes(value)) throw new Error("codeql_debug_policy_rejected");
    } else if (name.startsWith("CODEQL_")) {
      if (!allowedCodeql.has(name) || value !== allowedCodeql.get(name)) throw new Error("codeql_debug_policy_rejected");
    } else if (/^INPUT_(?:DEBUG|UPLOAD)(?:_|$)/.test(name)) {
      throw new Error("codeql_debug_policy_rejected");
    }
  }
  return { protocol: "aml-codeql-no-debug/1", debug_policy_valid: true };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    if (process.argv.length !== 2) throw new Error("invalid_arguments");
    process.stdout.write(JSON.stringify(assertNoCodeqlDebug()) + "\n");
  } catch {
    process.stderr.write('{"protocol":"aml-codeql-no-debug/1","debug_policy_valid":false}\n');
    process.exitCode = 1;
  }
}
