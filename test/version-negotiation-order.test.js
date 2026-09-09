import test from "node:test";
import assert from "node:assert/strict";
import { negotiateCapabilities, negotiateWireSession } from "../index.js";

const local = {
  versions: ["1.9", "1.10", "2.0"],
  capabilities: ["receipts", "wire"]
};
const remote = {
  versions: ["1.10", "1.9"],
  capabilities: ["wire", "receipts"]
};

test("capability negotiation selects 1.10 over 1.9", () => {
  const result = negotiateCapabilities(local, remote, { required: ["wire"] });
  assert.equal(result.compatible, true);
  assert.equal(result.selected_version, "1.10");
});

test("wire negotiation selects 1.10 over 1.9", () => {
  const result = negotiateWireSession(local, remote, ["wire"]);
  assert.equal(result.accepted, true);
  assert.equal(result.version, "1.10");
});

test("numeric dotted versions compare by numeric segments rather than string width", () => {
  const result = negotiateCapabilities(
    { versions: ["1.2", "1.2.10", "1.2.9"], capabilities: [] },
    { versions: ["1.2.9", "1.2.10"], capabilities: [] }
  );
  assert.equal(result.selected_version, "1.2.10");
});

test("non-numeric labels retain deterministic lexical fallback", () => {
  const result = negotiateWireSession(
    { versions: ["alpha", "beta"], capabilities: [] },
    { versions: ["beta", "alpha"], capabilities: [] }
  );
  assert.equal(result.version, "beta");
});
