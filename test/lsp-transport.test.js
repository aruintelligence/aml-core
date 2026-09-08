import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

function frame(message) {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
}

function parseFirstFrame(buffer) {
  const headerEnd = buffer.indexOf("\r\n\r\n");
  if (headerEnd < 0) return null;
  const header = buffer.slice(0, headerEnd);
  const match = header.match(/Content-Length:\s*(\d+)/i);
  if (!match) return null;
  const length = Number(match[1]);
  const bodyStart = headerEnd + 4;
  if (Buffer.byteLength(buffer.slice(bodyStart)) < length) return null;
  return JSON.parse(buffer.slice(bodyStart, bodyStart + length));
}

test("aml-lsp stdio transport answers initialize", async () => {
  const child = spawn(process.execPath, ["bin/aml-lsp.js"], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", chunk => { stdout += chunk; });
  child.stderr.on("data", chunk => { stderr += chunk; });

  child.stdin.write(frame({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }));

  const response = await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error(`Timed out waiting for aml-lsp response. stderr=${stderr}`)), 3000);
    const poll = setInterval(() => {
      const parsed = parseFirstFrame(stdout);
      if (parsed) {
        clearInterval(poll);
        clearTimeout(deadline);
        resolve(parsed);
      }
    }, 10);
  });

  child.stdin.write(frame({ jsonrpc: "2.0", method: "exit", params: {} }));

  assert.equal(response.id, 1);
  assert.equal(response.result.serverInfo.name, "ĀML Language Server");
  assert.equal(response.result.capabilities.hoverProvider, true);
});
