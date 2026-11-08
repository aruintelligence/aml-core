#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const extensions = {
  "javascript-typescript": new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]),
  python: new Set([".py"])
};
const failure = code => Object.assign(new Error(code), { code });
const canonical = p => typeof p === "string" && p.length > 0 && !/[\\\0\r\n]/.test(p)
  && !p.startsWith("/") && !p.split("/").some(part => ["", ".", ".."].includes(part));

// Genuine decoded query rows, not SARIF artifact presence or scanner metadata.
// Result is deliberately aggregate-only; raw paths/rows/errors are never returned.
export function compareExtractionInventory(tracked, inventory, language) {
  if (!Object.hasOwn(extensions, language)) throw failure("unsupported_language");
  if (!Array.isArray(tracked) || !tracked.every(canonical)
      || new Set(tracked).size !== tracked.length) throw failure("invalid_tracked_set");
  const expected = tracked.filter(p => extensions[language].has(path.posix.extname(p)));
  if (!expected.length) throw failure("empty_expected_set");
  const table = inventory?.["#select"];
  if (!table || !Array.isArray(table.columns) || table.columns.length !== 2
      || table.columns[0]?.kind !== "String" || table.columns[1]?.kind !== "Integer"
      || !Array.isArray(table.tuples)) throw failure("invalid_inventory");
  const counts = new Map();
  for (const row of table.tuples) {
    if (!Array.isArray(row) || row.length !== 2 || !canonical(row[0])
        || !Number.isSafeInteger(row[1]) || row[1] < 0 || counts.has(row[0])) {
      throw failure("invalid_inventory");
    }
    counts.set(row[0], row[1]);
  }
  const missing = expected.filter(p => !counts.has(p)).length;
  const zero = expected.filter(p => counts.get(p) === 0).length;
  const positive = expected.filter(p => counts.get(p) > 0).length;
  return { protocol: "aml-codeql-extraction/1", language, expected_files: expected.length,
    positive_files: positive, missing_files: missing, zero_ast_files: zero,
    extraction_complete: missing === 0 && zero === 0 && positive === expected.length };
}

export function verifyExtraction(cli, databaseRoot, language) {
  if (!Object.hasOwn(extensions, language)) throw failure("unsupported_language");
  const lang = language === "javascript-typescript" ? "javascript" : "python";
  const source = spawnSync("git", ["ls-files", "-z"], { encoding: null, maxBuffer: 16 * 1024 * 1024 });
  if (source.status !== 0 || !source.stdout) throw failure("tracked_inventory_failed");
  const tracked = new TextDecoder("utf-8", { fatal: true }).decode(source.stdout).split("\0").filter(Boolean);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "aml-codeql-inventory-"));
  try {
    const bqrs = path.join(temporary, "inventory.bqrs"), decoded = path.join(temporary, "inventory.json");
    function run(name, args) {
      const out = fs.openSync(path.join(temporary, name + ".stdout"), "wx", 0o600);
      const err = fs.openSync(path.join(temporary, name + ".stderr"), "wx", 0o600);
      try {
        const result = spawnSync(cli, args, { stdio: ["ignore", out, err], timeout: 180_000 });
        if (result.status !== 0) throw failure(name + "_failed");
      } finally { fs.closeSync(out); fs.closeSync(err); }
    }
    run("query", ["query", "run", path.join(root, ".github/codeql/extraction-inventory", lang, "inventory.ql"),
      "--database=" + path.join(databaseRoot, lang), "--output=" + bqrs, "--threads=2", "--ram=4096"]);
    run("decode", ["bqrs", "decode", bqrs, "--format=json", "--output=" + decoded]);
    if (fs.statSync(decoded).size > 32 * 1024 * 1024) throw failure("invalid_inventory");
    return compareExtractionInventory(tracked, JSON.parse(fs.readFileSync(decoded, "utf8")), language);
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    if (process.argv.length !== 5) throw failure("invalid_arguments");
    const result = verifyExtraction(process.argv[2], process.argv[3], process.argv[4]);
    process.stdout.write(JSON.stringify(result) + "\n");
    if (!result.extraction_complete) process.exitCode = 1;
  } catch {
    // Neither child output, filenames, decoded rows nor exception details escape.
    process.stderr.write('{"protocol":"aml-codeql-extraction/1","extraction_complete":false}\n');
    process.exitCode = 1;
  }
}
