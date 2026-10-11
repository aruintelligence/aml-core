import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("the published visual board carries the exact challenge contract bytes", () => {
  const manifest = readFileSync(new URL("../conformance/action-boundary-challenge.json", import.meta.url));
  const board = readFileSync(new URL("../docs/action-challenge-board.json", import.meta.url));
  assert.deepEqual(board, manifest, "Update the board copy whenever the canonical contract changes");

  const challenge = JSON.parse(board);
  assert.equal(challenge.protocol, "aml-action-boundary-challenge/1");
  assert.equal(challenge.cases.length, 13);
  assert.equal(new Set(challenge.cases.map(row => row.id)).size, 13);
  assert.ok(challenge.cases.every(row => ["blocked", "dispatched", "unknown"].includes(row.expected.status)));
  assert.equal(challenge.command_contract.no_live_tools, true);
});
