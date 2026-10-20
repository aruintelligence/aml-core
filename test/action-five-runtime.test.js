import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";

const read = file => readFileSync(new URL(`../${file}`, import.meta.url));
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const casesBytes = read("conformance/action-boundary-expanded-cases.json");
const cases = JSON.parse(casesBytes);
const report = JSON.parse(read("docs/action-five-runtime-report.json"));

test("five recorded outcomes match every exact challenge decision and digest", () => {
  assert.equal(report.protocol, "aml-action-five-runtime-matrix/1");
  assert.equal(report.cases_file_sha256, sha(casesBytes));
  assert.equal(report.case_count, 100);
  assert.equal(report.rows.length, 100);
  assert.deepEqual(Object.values(report.matches_by_runtime), [100, 100, 100, 100, 100]);
  for (const [i, row] of report.rows.entries()) {
    assert.equal(row.case_id, cases.cases[i].id);
    for (const outcome of Object.values(row.outcomes)) {
      assert.equal(outcome.proposal_sha256, cases.cases[i].expected.plan.proposal_sha256);
      assert.equal(outcome.decision, cases.cases[i].expected.plan.decision);
      assert.equal(outcome.gate_outcome, cases.cases[i].expected.tool_calls ? "ALLOW" : "SUPPRESS");
      assert.equal(outcome.execution_status, cases.cases[i].expected.receipt.execution_status);
      assert.equal(outcome.tool_calls, cases.cases[i].expected.tool_calls);
    }
  }
  for (const [name, file] of Object.entries({
    javascript_node: "pilots/action-boundary/boundary.mjs",
    python_hashlib: "pilots/action-boundary/python_boundary.py",
    perl_digest_sha: "pilots/action-boundary/perl_boundary.pl",
    python_openssl: "pilots/action-boundary/openssl_python_boundary.py",
    webcrypto_node_host: "docs/action-webcrypto-boundary.js"
  })) assert.equal(report.source_sha256[name], sha(read(file)));
});

test("browser loads exact published corpus bytes and pins the full corpus hash", () => {
  assert.deepEqual(read("docs/action-browser-cases.json"), casesBytes);
  const html = read("docs/action-browser-matrix.html").toString("utf8");
  assert.match(html, /import \{ runWebCryptoCase \} from '\.\/action-webcrypto-boundary\.js'/);
  assert.ok(html.includes(sha(casesBytes)));
  assert.match(html, /crypto\.subtle\.digest\('SHA-256', bytes\)/);
});
