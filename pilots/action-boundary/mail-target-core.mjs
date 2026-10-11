// Browser-compatible normalization for one narrow mail tool schema.
// The generated docs copy is byte-for-byte identical to this source.
const allowed = new Set(["to", "cc", "bcc", "subject", "body"]);

function recipients(value, required) {
  const items = typeof value === "string" ? [value] : Array.isArray(value) ? value : null;
  if (!items || (required && items.length === 0) || items.length > 32 ||
      items.some(item => typeof item !== "string" || !item.trim() ||
        item !== item.trim() || item.length > 254)) throw new TypeError("invalid_mail_recipients");
  return [...items];
}

export function mailTargetBytes(args) {
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
  // This is the exact sorted-key JSON produced by canonicalJSONStringify for
  // this fixed object with string-only arrays; the parity test guards it.
  const bytes = JSON.stringify({ bcc: manifest.bcc, cc: manifest.cc,
    protocol: manifest.protocol, to: manifest.to });
  return { manifest, bytes };
}
