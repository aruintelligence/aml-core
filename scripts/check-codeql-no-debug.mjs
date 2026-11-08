#!/usr/bin/env node
import { pathToFileURL } from "node:url";

// Pinned CodeQL init ORs input debug with core.isDebug(); upload:never does not
// disable its separate debug post-action or combined-SARIF artifact path.
export function assertNoCodeqlDebug(env = process.env) {
  for (const [name, value] of Object.entries(env)) {
    if (/^(?:RUNNER_DEBUG|ACTIONS_STEP_DEBUG|ACTIONS_RUNNER_DEBUG|INPUT_DEBUG)$/.test(name)
        || /^CODEQL_.*DEBUG/.test(name)) {
      if (typeof value !== "string" || !["", "0", "false"].includes(value)) {
        throw new Error("codeql_debug_policy_rejected");
      }
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
