// tooling/lspCore.js
// Minimal dependency-free Language Server Protocol core for ĀML.

import { compileSource } from "../compiler/compiler.js";
import { analyzeAMT } from "../compiler/diagnostics.js";
import { getCompletionItems, getHoverInfo } from "./languageService.js";

export function createLspState() {
  return { documents: new Map() };
}

function wordAt(text, position) {
  const lines = text.split(/\r?\n/);
  const line = lines[position?.line ?? 0] ?? "";
  const character = Math.max(0, Math.min(position?.character ?? 0, line.length));
  const left = line.slice(0, character).match(/[A-Za-z0-9_Āā]+$/)?.[0] || "";
  const right = line.slice(character).match(/^[A-Za-z0-9_Āā]+/)?.[0] || "";
  return left + right;
}

function diagnosticRange(text, diagnostic) {
  const needle = diagnostic.identifier || diagnostic.name;
  if (!needle) return { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } };

  const lines = text.split(/\r?\n/);
  for (let line = 0; line < lines.length; line++) {
    const character = lines[line].indexOf(needle);
    if (character >= 0) {
      return {
        start: { line, character },
        end: { line, character: character + needle.length }
      };
    }
  }

  return { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } };
}

export function getDocumentDiagnostics(text) {
  try {
    const compiled = compileSource(text, { timestamp: "1970-01-01T00:00:00.000Z" });
    return analyzeAMT(compiled.amt).map(item => ({
      range: diagnosticRange(text, item),
      severity: item.level === "error" ? 1 : 2,
      code: item.code,
      source: "aml",
      message: item.message
    }));
  } catch (error) {
    return [{
      range: { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } },
      severity: 1,
      code: "AML_PARSE",
      source: "aml",
      message: error.message
    }];
  }
}

function completionKind(kind) {
  if (kind === "property") return 10;
  if (kind === "operator") return 24;
  return 14;
}

export function handleLspMessage(message, state = createLspState()) {
  const method = message?.method;
  const params = message?.params || {};

  if (method === "initialize") {
    return {
      response: {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          capabilities: {
            textDocumentSync: 1,
            completionProvider: { triggerCharacters: [":", " "] },
            hoverProvider: true
          },
          serverInfo: { name: "ĀML Language Server", version: "0.1.0" }
        }
      },
      notifications: []
    };
  }

  if (method === "shutdown") {
    return { response: { jsonrpc: "2.0", id: message.id, result: null }, notifications: [] };
  }

  if (method === "textDocument/didOpen") {
    const uri = params.textDocument.uri;
    const text = params.textDocument.text || "";
    state.documents.set(uri, text);
    return {
      response: null,
      notifications: [{
        jsonrpc: "2.0",
        method: "textDocument/publishDiagnostics",
        params: { uri, diagnostics: getDocumentDiagnostics(text) }
      }]
    };
  }

  if (method === "textDocument/didChange") {
    const uri = params.textDocument.uri;
    const text = params.contentChanges?.at(-1)?.text ?? state.documents.get(uri) ?? "";
    state.documents.set(uri, text);
    return {
      response: null,
      notifications: [{
        jsonrpc: "2.0",
        method: "textDocument/publishDiagnostics",
        params: { uri, diagnostics: getDocumentDiagnostics(text) }
      }]
    };
  }

  if (method === "textDocument/didClose") {
    const uri = params.textDocument.uri;
    state.documents.delete(uri);
    return {
      response: null,
      notifications: [{
        jsonrpc: "2.0",
        method: "textDocument/publishDiagnostics",
        params: { uri, diagnostics: [] }
      }]
    };
  }

  if (method === "textDocument/completion") {
    const uri = params.textDocument.uri;
    const text = state.documents.get(uri) || "";
    const prefix = wordAt(text, params.position);
    const items = getCompletionItems(prefix).map(item => ({
      label: item.label,
      kind: completionKind(item.kind),
      detail: `ĀML ${item.kind}`,
      documentation: item.documentation,
      insertText: item.label
    }));
    return { response: { jsonrpc: "2.0", id: message.id, result: { isIncomplete: false, items } }, notifications: [] };
  }

  if (method === "textDocument/hover") {
    const uri = params.textDocument.uri;
    const text = state.documents.get(uri) || "";
    const symbol = wordAt(text, params.position);
    const hover = getHoverInfo(symbol);
    return {
      response: {
        jsonrpc: "2.0",
        id: message.id,
        result: hover ? { contents: { kind: "markdown", value: `**${hover.symbol}** — ${hover.documentation}` } } : null
      },
      notifications: []
    };
  }

  if (message.id !== undefined) {
    return {
      response: {
        jsonrpc: "2.0",
        id: message.id,
        error: { code: -32601, message: `Method not found: ${method}` }
      },
      notifications: []
    };
  }

  return { response: null, notifications: [] };
}
