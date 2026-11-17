// Test-only abrupt process death around real read-only verifier/checker calls.
import fs from "node:fs";
import { summarizeCodeql } from "../../scripts/check-codeql-sarif.mjs";
import { verifyProviderStatus } from "../../pilots/action-boundary/verify-provider-status.mjs";
const [kind, fault] = process.argv.slice(2);
if (!["sarif", "provider"].includes(kind) || !["before", "after"].includes(fault)) throw Error("invalid_test_mode");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
if (fault === "before") process.kill(process.pid, "SIGKILL");
const result = kind === "sarif" ? summarizeCodeql(input, "javascript-typescript") : verifyProviderStatus(input.envelope, input.expected);
if (kind === "provider" && result !== "PROVIDER_REPORTED") throw Error("test_needs_real_positive_control");
if (kind === "sarif" && !result.analysis_quality_valid) throw Error("test_needs_valid_format_control");
process.kill(process.pid, "SIGKILL"); // No status is returned or persisted.
