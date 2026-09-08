import test from "node:test";
import assert from "node:assert/strict";

import { createLspState, handleLspMessage, getDocumentDiagnostics } from "../tooling/lspCore.js";

const uri = "file:///demo.aml";
const source = `transmission "demo" {\n  engram Card {\n    purpose: "Explain something."\n    attention_cost: 2\n    restoration_value: 8\n  }\n}\n`;

test("AML LSP initialize advertises completion, hover, and sync", () => {
  const state = createLspState();
  const result = handleLspMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, state);
  assert.equal(result.response.result.capabilities.hoverProvider, true);
  assert.ok(result.response.result.capabilities.completionProvider);
  assert.equal(result.response.result.capabilities.textDocumentSync, 1);
});

test("AML LSP publishes semantic diagnostics when documents open", () => {
  const state = createLspState();
  const result = handleLspMessage({
    jsonrpc: "2.0",
    method: "textDocument/didOpen",
    params: { textDocument: { uri, text: source } }
  }, state);
  assert.equal(state.documents.get(uri), source);
  assert.equal(result.notifications[0].method, "textDocument/publishDiagnostics");
  assert.deepEqual(result.notifications[0].params.diagnostics, []);
});

test("AML LSP completion and hover use the shared language catalog", () => {
  const state = createLspState();
  state.documents.set(uri, "rest");
  const completion = handleLspMessage({
    jsonrpc: "2.0", id: 2, method: "textDocument/completion",
    params: { textDocument: { uri }, position: { line: 0, character: 4 } }
  }, state);
  assert.ok(completion.response.result.items.some(item => item.label === "restoration_value"));

  state.documents.set(uri, "purpose");
  const hover = handleLspMessage({
    jsonrpc: "2.0", id: 3, method: "textDocument/hover",
    params: { textDocument: { uri }, position: { line: 0, character: 3 } }
  }, state);
  assert.match(hover.response.result.contents.value, /purpose/);
});

test("AML LSP converts parse failures to diagnostics", () => {
  const diagnostics = getDocumentDiagnostics('transmission "broken" {');
  assert.equal(diagnostics[0].code, "AML_PARSE");
  assert.equal(diagnostics[0].severity, 1);
});
