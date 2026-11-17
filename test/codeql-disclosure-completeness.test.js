import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertNoCodeqlDebug } from "../scripts/check-codeql-no-debug.mjs";
import { compareExtractionInventory, readExtractionInventory } from "../scripts/check-codeql-extraction.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const guard = path.join(root, "scripts/check-codeql-no-debug.mjs");
const extraction = path.join(root, "scripts/check-codeql-extraction.mjs");
const table = tuples => ({ "#select": { columns: [{ kind: "String" }, { kind: "Integer" }], tuples } });
const four = ["scripts/build-a2ui-worker-report.mjs", "scripts/build-connected-mcp-report.mjs",
  "scripts/build-mcp-call-report.mjs", "scripts/render-action-challenge-report.mjs"];

test("normal/explicitly disabled debug configuration is permitted, not a scanner claim", () => {
  assert.equal(assertNoCodeqlDebug({}).debug_policy_valid, true);
  for (const value of ["", "0", "false"]) assert.equal(assertNoCodeqlDebug({ RUNNER_DEBUG: value,
    CODEQL_ACTION_DEBUG_COMBINED_SARIF: value, INPUT_DEBUG: value }).debug_policy_valid, true);
  assert.equal(assertNoCodeqlDebug({ UNRELATED_DEBUG_SETTING: "true" }).debug_policy_valid, true);
});
for (const name of ["RUNNER_DEBUG", "ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG", "INPUT_DEBUG",
  "CODEQL_ACTION_DEBUG_COMBINED_SARIF", "CODEQL_ACTION_JAVA_NETWORK_DEBUGGING",
  "CODEQL_UNEXPECTED_DEBUG_UPLOAD_MODE", "CODEQL_EXTRACTOR_JAVASCRIPT_DEBUG"]) {
  test(`enabled or ambiguous debug setting fails closed: ${name}`, () => {
    for (const value of ["1", "true", "TRUE", "unexpected", "false ", null]) {
      assert.throws(() => assertNoCodeqlDebug({ [name]: value }), /codeql_debug_policy_rejected/);
    }
  });
}
test("pre-init CLI rejects runner and combined-SARIF modes with fixed non-sensitive output", () => {
  for (const env of [{ RUNNER_DEBUG: "1" }, { CODEQL_ACTION_DEBUG_COMBINED_SARIF: "true" },
    { CODEQL_FUTURE_DEBUG_MODE: "SYNTHETIC_PRIVATE_CANARY" },
    { "INPUT_DEBUG-ARTIFACT-NAME": "SYNTHETIC_PRIVATE_CANARY" },
    { "INPUT_DEBUG-DATABASE-NAME": "SYNTHETIC_PRIVATE_CANARY" },
    { "INPUT_UPLOAD-DATABASE": "SYNTHETIC_PRIVATE_CANARY" }]) {
    const result = spawnSync(process.execPath, [guard], { env: { PATH: process.env.PATH, ...env }, encoding: "utf8" });
    assert.equal(result.status, 1); assert.equal(result.stdout, "");
    assert.deepEqual(JSON.parse(result.stderr), { protocol: "aml-codeql-no-debug/1", debug_policy_valid: false });
    assert.doesNotMatch(result.stderr, /CANARY|\.mjs|\bat /);
  }
});
function assertWorkflowPolicy(text) {
  const guardAt = text.indexOf("      - name: Enforce no-debug disclosure policy before scanner initialization");
  const initAt = text.indexOf("      - name: Initialize CodeQL security-extended analysis");
  const analyzeAt = text.indexOf("      - name: Run actual CodeQL queries without Code Scanning upload");
  const inventoryAt = text.indexOf("      - name: Verify tracked source AST and module extraction");
  assert.ok(guardAt >= 0 && initAt > guardAt && analyzeAt > initAt && inventoryAt > analyzeAt);
  const guardBlock = text.slice(guardAt, initAt), initBlock = text.slice(initAt, analyzeAt);
  assert.match(guardBlock, /run: node scripts\/check-codeql-no-debug\.mjs\n$/);
  assert.equal((guardBlock.match(/      - name:/g) ?? []).length, 1);
  assert.doesNotMatch(guardBlock, /\n        (?:if|env|continue-on-error):/);
  assert.doesNotMatch(initBlock, /\n        (?:if|env|continue-on-error):/);
  assert.match(initBlock, /debug: false/); assert.match(initBlock, /id: codeql-init/);
  assert.match(initBlock, /db-location: \$\{\{ runner.temp \}\}\/aml-codeql-db/);
  const inventoryBlock = text.slice(inventoryAt).split("      # Raw reports")[0];
  assert.match(inventoryBlock, /run: node scripts\/check-codeql-extraction\.mjs/);
  assert.doesNotMatch(inventoryBlock, /\n        (?:if|continue-on-error):/);
  assert.match(inventoryBlock, /steps.codeql-init.outputs.codeql-path/);
  assert.doesNotMatch(text, /CODEQL_\w*DEBUG|RUNNER_DEBUG:|ACTIONS_STEP_DEBUG:|upload-artifact|continue-on-error:/);
}
test("workflow policy detects removed/reordered/skipped/debug-overridden gates", () => {
  const source = fs.readFileSync(path.join(root, ".github/workflows/codeql.yml"), "utf8");
  assertWorkflowPolicy(source);
  for (const mutation of [
    s => s.replace("run: node scripts/check-codeql-no-debug.mjs", "run: true"),
    s => s.replace("Enforce no-debug disclosure policy before scanner initialization", "Unrelated successful step"),
    s => s.replace("        run: node scripts/check-codeql-no-debug.mjs", "        if: false\n        run: node scripts/check-codeql-no-debug.mjs"),
    s => s.replace("          debug: false", "          debug: true"),
    s => s.replace("        id: codeql-init", "        env:\n          RUNNER_DEBUG: '1'\n        id: codeql-init"),
    s => s.replace("          debug: false", "          debug: false\n          CODEQL_ACTION_DEBUG_COMBINED_SARIF: true"),
    s => s.replace("      - name: Verify tracked source AST and module extraction", "      - name: Verify tracked source AST and module extraction\n        if: false"),
    s => s.replace("run: node scripts/check-codeql-extraction.mjs", "run: true #"),
    s => s.replace("      - name: Initialize CodeQL", "      - name: Unexpected intermediate step\n        run: true\n      - name: Initialize CodeQL")
  ]) assert.throws(() => assertWorkflowPolicy(mutation(source)), assert.AssertionError);
});
test("actual decoded rows must cover every tracked source, including each formerly missed script", () => {
  assert.equal(compareExtractionInventory(four, table(four.map(p => [p, 1])), "javascript-typescript").extraction_complete, true);
  for (const missing of four) {
    const rows = four.map(p => [p, p === missing ? 0 : 1]);
    assert.equal(compareExtractionInventory(four, table(rows), "javascript-typescript").extraction_complete, false);
    assert.equal(compareExtractionInventory(four, table(rows.filter(([p]) => p !== missing)), "javascript-typescript").missing_files, 1);
  }
  const py = compareExtractionInventory(["one.py", "README.md"], table([["one.py", 1], ["README.md", 0]]), "python");
  assert.equal(py.expected_files, 1); assert.equal(py.extraction_complete, true);
});
test("metadata/presence, null/duplicate/negative/fractional/unsafe inventory data never pass", () => {
  for (const invalid of [null, {}, { artifacts: four }, { "#select": null }, table(null),
    table([["one.py", 1], ["one.py", 1]]), table([["one.py", -1]]), table([["one.py", 0.5]]),
    table([["one.py", Number.MAX_SAFE_INTEGER + 1]]), table([["../one.py", 1]]), table([["one.py", "1"]])]) {
    assert.throws(() => compareExtractionInventory(["one.py"], invalid, "python"));
  }
  assert.throws(() => compareExtractionInventory([], table([]), "python"));
  assert.throws(() => compareExtractionInventory(["one.py", "one.py"], table([]), "python"));
  assert.throws(() => compareExtractionInventory(["one.py"], table([]), "unknown"));
});
for (const mode of ["good", "query_fail", "decode_fail", "missing", "zero", "malformed"]) {
  test(`extraction CLI dependency-stub ${mode}: no raw child/path/error canary emitted`, () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inventory-stub-"));
    try {
      fs.writeFileSync(path.join(tmp, "source.mjs"), "void 0;\n");
      for (const args of [["init", "-q"], ["add", "source.mjs"]]) assert.equal(spawnSync("git", args, { cwd: tmp }).status, 0);
      const stub = path.join(tmp, "codeql-stub.mjs");
      fs.writeFileSync(stub, `#!${process.execPath}\nimport fs from 'node:fs';
const a=process.argv.slice(2),out=a.find(x=>x.startsWith('--output='))?.slice(9);
process.stdout.write('SYNTHETIC_PRIVATE_SOURCE_CANARY');process.stderr.write('SYNTHETIC_PRIVATE_STACK_CANARY');
if(a[0]==='query'){if(process.env.STUB_MODE==='query_fail')process.exit(2);fs.writeFileSync(out,'stub bqrs');}
else{if(process.env.STUB_MODE==='decode_fail')process.exit(2);fs.writeFileSync(out,process.env.STUB_MODE==='malformed'?'not JSON':JSON.stringify({'#select':{columns:[{kind:'String'},{kind:'Integer'}],tuples:process.env.STUB_MODE==='missing'?[]:[['source.mjs',process.env.STUB_MODE==='zero'?0:1],['SYNTHETIC_PRIVATE_SOURCE_CANARY.mjs',1]]}}));}
`, { mode: 0o700 });
      const run = spawnSync(process.execPath, [extraction, stub, path.join(tmp, "db"), "javascript-typescript"],
        { cwd: tmp, env: { PATH: process.env.PATH, STUB_MODE: mode }, encoding: "utf8", timeout: 20_000 });
      assert.equal(run.status, mode === "good" ? 0 : 1);
      const output = run.stdout + run.stderr; assert.doesNotMatch(output, /CANARY|source\.mjs|\.ql|\bat /);
      const result = JSON.parse(output); assert.equal(result.extraction_complete, mode === "good");
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });
}

test("decoded inventory reads the checked descriptor, not a substituted symlink", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inventory-fd-"));
  const file = path.join(tmp, "inventory.json"), other = path.join(tmp, "other.json");
  const expected = table([["one.py", 1]]);
  fs.writeFileSync(file, JSON.stringify(expected)); fs.writeFileSync(other, "SYNTHETIC_PRIVATE_CANARY");
  const original = { open: fs.openSync, stat: fs.fstatSync, read: fs.readFileSync };
  let fd, swapped = false, wholeReads = 0;
  fs.openSync = function(p, ...args) { const result = original.open.call(this, p, ...args); if (p === file) fd = result; return result; };
  fs.fstatSync = function(target, ...args) { const info = original.stat.call(this, target, ...args); if (target === fd && !swapped) { swapped = true; fs.unlinkSync(file); fs.symlinkSync(other, file); } return info; };
  fs.readFileSync = function(p, ...args) { if (p === file || p === fd) wholeReads++; return original.read.call(this, p, ...args); };
  try { assert.deepEqual(readExtractionInventory(file), expected); assert.equal(wholeReads, 0); assert.throws(() => readExtractionInventory(file)); }
  finally { fs.openSync = original.open; fs.fstatSync = original.stat; fs.readFileSync = original.read; fs.rmSync(tmp, { recursive: true, force: true }); }
});
test("decoded inventory same-inode growth is finite, rejected and does not leak its descriptor", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aml-inventory-growth-")), file = path.join(tmp, "inventory.json");
  const initial = JSON.stringify(table([["one.py", 1]])); fs.writeFileSync(file, initial);
  const original = { open: fs.openSync, stat: fs.fstatSync, read: fs.readSync, whole: fs.readFileSync };
  let fd, grew = false, largestRead = 0, wholeReads = 0;
  fs.openSync = function(p, flags, ...args) { const result = original.open.call(this, p, flags, ...args); if (p === file && typeof flags === "number") fd = result; return result; };
  fs.fstatSync = function(target, ...args) { const info = original.stat.call(this, target, ...args); if (target === fd && !grew) { grew = true; fs.appendFileSync(file, " ".repeat(8192)); } return info; };
  fs.readSync = function(target, buffer, offset, length, ...args) { if (target === fd) largestRead = Math.max(largestRead, length); return original.read.call(this, target, buffer, offset, length, ...args); };
  fs.readFileSync = function(p, ...args) { if (p === file || p === fd) wholeReads++; return original.whole.call(this, p, ...args); };
  try {
    assert.throws(() => readExtractionInventory(file), /regular_file_changed_during_read/);
    assert.equal(wholeReads, 0); assert.ok(largestRead <= Buffer.byteLength(initial) + 1);
    assert.throws(() => original.read(fd, Buffer.alloc(1), 0, 1, 0), /EBADF/);
    assert.equal(original.whole(file, "utf8"), initial + " ".repeat(8192));
  } finally { fs.openSync = original.open; fs.fstatSync = original.stat; fs.readSync = original.read; fs.readFileSync = original.whole; fs.rmSync(tmp, { recursive: true, force: true }); }
});

test("unexpected CODEQL/debug-upload inputs reject even false-looking values; known modes are pinned", () => {
  for (const name of ["CODEQL_FUTURE_DEBUG_MODE", "CODEQL_ACTION_EXPECT_UPLOAD_FAILED_SARIF",
    "CODEQL_ACTION_UNKNOWN_UPLOAD_MODE", "CODEQL_ACTION_FEATURE_FLAGS", "INPUT_DEBUG_ARTIFACT_NAME",
    "INPUT_DEBUG_DATABASE_NAME", "INPUT_UPLOAD", "INPUT_UPLOAD_DATABASE"]) {
    for (const value of ["", "false", "0", "true", "SYNTHETIC_PRIVATE_VALUE"]) {
      assert.throws(() => assertNoCodeqlDebug({ [name]: value }), /codeql_debug_policy_rejected/);
    }
  }
  assert.equal(assertNoCodeqlDebug({ CODEQL_ACTION_DIFF_INFORMED_QUERIES: "false", CODEQL_ACTION_OVERLAY_ANALYSIS: "false",
    CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES: "true" }).debug_policy_valid, true);
  for (const env of [{ CODEQL_ACTION_DIFF_INFORMED_QUERIES: "true" }, { CODEQL_ACTION_OVERLAY_ANALYSIS: "true" },
    { CODEQL_EXTRACTOR_JAVASCRIPT_ALLOW_MINIFIED_FILES: "false" }]) assert.throws(() => assertNoCodeqlDebug(env));
});

for (const name of ["INPUT_DEBUG-ARTIFACT-NAME", "INPUT_DEBUG-DATABASE-NAME", "INPUT_UPLOAD-DATABASE"]) {
  test(`actual hyphenated debug/upload selector fails closed: ${name}`, () => {
    for (const value of ["", "0", "false", "true", "SYNTHETIC_PRIVATE_VALUE"]) {
      assert.throws(() => assertNoCodeqlDebug({ [name]: value }), /codeql_debug_policy_rejected/);
    }
  });
}
test("entire debug/upload input prefix rejects every tested suffix without relaxing exact disabled debug", () => {
  for (const value of ["", "0", "false"]) assert.equal(assertNoCodeqlDebug({ INPUT_DEBUG: value }).debug_policy_valid, true);
  for (const prefix of ["INPUT_DEBUG", "INPUT_UPLOAD"]) {
    for (const suffix of ["-ARTIFACT-NAME", "-DATABASE-NAME", "_ARTIFACT_NAME", "_DATABASE_NAME", "EXTRA", "NEW",
      "-", "_", ".MODE", ":MODE", "/MODE", " MODE", "0", "\u03a9"]) {
      for (const value of ["", "0", "false", "true", null, undefined, 1, {}]) {
        assert.throws(() => assertNoCodeqlDebug({ [prefix + suffix]: value }), /codeql_debug_policy_rejected/);
      }
    }
  }
});
