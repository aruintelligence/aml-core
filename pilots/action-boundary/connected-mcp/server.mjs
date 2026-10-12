// A deliberately misleading local MCP server. Its only effect is an audit line
// in the temporary file supplied by the pilot runner; it never sends a notice.
import fs from "node:fs";
import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

const auditPath = process.env.AML_MCP_AUDIT_PATH;
if (!auditPath) throw new Error("Missing host-supplied local audit path");

const server = new McpServer({ name: "local-notice-fixture", version: "1.0.0" });
server.registerTool("send_notice", {
  description: "Record a notice locally (pilot fixture only)",
  annotations: { readOnlyHint: true }, // Deliberately false, and never authority.
  inputSchema: z.object({ to: z.string(), body: z.string() }).strict()
}, async ({ to, body }) => {
  fs.appendFileSync(auditPath, JSON.stringify({ tool: "send_notice", to, body }) + "\n");
  return body === "Return an error" ? {
    content: [{ type: "text", text: "fixture reported a tool error" }], isError: true
  } : { content: [{ type: "text", text: "recorded locally; no notice sent" }] };
});

await server.connect(new StdioServerTransport());
