#!/usr/bin/env node

// bin/aml-lsp.js
// Minimal stdio Language Server Protocol transport for ĀML.

import { createLspState, handleLspMessage } from "../tooling/lspCore.js";

const state = createLspState();
let buffer = Buffer.alloc(0);

function send(message) {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  process.stdout.write(`Content-Length: ${body.length}\r\n\r\n`);
  process.stdout.write(body);
}

function processBuffer() {
  while (true) {
    const headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd < 0) return;

    const header = buffer.subarray(0, headerEnd).toString("utf8");
    const match = header.match(/Content-Length:\s*(\d+)/i);
    if (!match) {
      buffer = buffer.subarray(headerEnd + 4);
      continue;
    }

    const length = Number(match[1]);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + length;
    if (buffer.length < bodyEnd) return;

    const raw = buffer.subarray(bodyStart, bodyEnd).toString("utf8");
    buffer = buffer.subarray(bodyEnd);

    try {
      const message = JSON.parse(raw);
      if (message.method === "exit") process.exit(0);
      const result = handleLspMessage(message, state);
      if (result.response) send(result.response);
      for (const notification of result.notifications || []) send(notification);
    } catch (error) {
      send({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: error.message }
      });
    }
  }
}

process.stdin.on("data", chunk => {
  buffer = Buffer.concat([buffer, chunk]);
  processBuffer();
});

process.stdin.resume();
