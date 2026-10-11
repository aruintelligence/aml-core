// Example host adapter for one deliberately narrow mail tool schema.
// The real callback must use exactly these destination fields and reject any
// other delivery route. A digest is a comparison key, not authorization.
import crypto from "node:crypto";
import { mailTargetBytes } from "./mail-target-core.mjs";

export function mailTargetResource(args) {
  const { manifest, bytes } = mailTargetBytes(args);
  return { manifest, resource: "mail-targets-sha256:" +
    crypto.createHash("sha256").update(bytes, "utf8").digest("hex") };
}

export function resolveMailTarget({ tool, effect, arguments: args }) {
  if (tool !== "send_message" || effect !== "send") throw new TypeError("unsupported_mail_tool");
  return mailTargetResource(args).resource;
}
