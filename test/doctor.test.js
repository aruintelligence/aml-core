import test from "node:test";
import assert from "node:assert/strict";
import { runAmlDoctor } from "../tooling/doctor.js";

test("AML doctor reports a healthy local package/runtime", () => {
  const report = runAmlDoctor();
  assert.equal(report.protocol, "aml-doctor-report/1");
  assert.equal(report.package, "aml-core");
  assert.equal(report.healthy, true);
  assert.ok(report.checks.length >= 4);
  assert.equal(report.checks.every(check => check.ok === true), true);
  assert.match(report.claim_boundary, /Local package\/runtime health only/);
});
