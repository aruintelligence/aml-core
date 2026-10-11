// Example host adapter for one deliberately narrow mail tool schema.
// The real callback must use exactly these destination fields and reject any
// other delivery route. A digest is a comparison key, not authorization.
import crypto from "node:crypto";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";

const allowed = new Set(["to", "cc", "bcc", "subject", "body"]);

function recipients(value, required) {
  const items = typeof value === "string" ? [value] : Array.isArray(value) ? value : null;
  if (!items || (required && items.length === 0) || items.length > 32 ||
      items.some(item => typeof item !== "string" || !item.trim() ||
        item !== item.trim() || item.length > 254)) throw new TypeError("invalid_mail_recipients");
  return [...items];
}

export function mailTargetResource(args) {
  if (!args || typeof args !== "object" || Array.isArray(args) ||
      Object.getPrototypeOf(args) !== Object.prototype ||
      Object.keys(args).some(key => !allowed.has(key)) ||
      (args.subject !== undefined && typeof args.subject !== "string") ||
      (args.body !== undefined && typeof args.body !== "string")) {
    throw new TypeError("unsupported_mail_arguments");
  }
  const manifest = { protocol: "aml-mail-target-manifest/1",
    to: recipients(args.to, true), cc: recipients(args.cc === undefined ? [] : args.cc, false),
    bcc: recipients(args.bcc === undefined ? [] : args.bcc, false) };
  const bytes = canonicalJSONStringify(manifest);
  return { manifest, resource: "mail-targets-sha256:" +
    crypto.createHash("sha256").update(bytes, "utf8").digest("hex") };
}

export function resolveMailTarget({ tool, effect, arguments: args }) {
  if (tool !== "send_message" || effect !== "send") throw new TypeError("unsupported_mail_tool");
  return mailTargetResource(args).resource;
}
