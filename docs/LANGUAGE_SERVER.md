# ĀML™ Language Server

ĀML v1.1 includes a minimal dependency-free Language Server Protocol implementation over stdio.

Run it with:

```bash
npm run lsp
```

or, when installed as a package binary:

```bash
aml-lsp
```

## Current LSP surface

The server implements:

- `initialize`
- `shutdown`
- `exit`
- `textDocument/didOpen`
- `textDocument/didChange`
- `textDocument/didClose`
- `textDocument/completion`
- `textDocument/hover`
- `textDocument/publishDiagnostics`

It advertises full-document synchronization, completion support, and hover support.

## Live diagnostics

When an AML document opens or changes, the server compiles it in memory and publishes either:

- semantic diagnostics such as `AML001`–`AML005`; or
- `AML_PARSE` when the document cannot be parsed.

This means editor diagnostics are driven by the same compiler and semantic-analysis code used by the CLI rather than a separate regex-based validator.

## Completion + hover

The LSP consumes the shared language-intelligence catalog. Completion and hover terminology therefore stays aligned with the programmatic editor API.

## Transport

`bin/aml-lsp.js` implements JSON-RPC 2.0 message framing using standard `Content-Length` headers over stdin/stdout.

The protocol core lives separately in `tooling/lspCore.js`, allowing it to be tested without spawning an editor process.

## Current boundary

This is an early language server, not yet a complete production IDE integration. Current gaps include:

- incremental text synchronization;
- workspace indexing;
- go-to-definition;
- references and rename;
- code actions;
- formatting;
- semantic tokens;
- automatic VS Code client activation.

The important architectural step is already in place: AML now has one compiler-backed intelligence layer that can serve CLI tools, editors, agents, and LSP clients.
