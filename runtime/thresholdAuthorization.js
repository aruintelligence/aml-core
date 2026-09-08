import crypto from "node:crypto";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

function fingerprint(publicKey) {
  return crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
}

export function createThresholdAuthorization(payload, privateKeys, { threshold, context = "aml-threshold-authorization/1" } = {}) {
  if (!Number.isInteger(threshold) || threshold < 1) throw new Error("threshold must be a positive integer");
  if (!Array.isArray(privateKeys) || privateKeys.length < threshold) throw new Error("not enough signing keys for threshold");

  const message = Buffer.from(canonicalJSONStringify({ context, payload }));
  const signatures = privateKeys.map((pem) => {
    const privateKey = crypto.createPrivateKey(pem);
    const publicKey = crypto.createPublicKey(privateKey);
    return {
      key_fingerprint: fingerprint(publicKey),
      public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      signature_base64: crypto.sign(null, message, privateKey).toString("base64")
    };
  });

  return { type: context, threshold, payload, signatures };
}

export function verifyThresholdAuthorization(authorization) {
  if (!authorization || !Number.isInteger(authorization.threshold) || authorization.threshold < 1) {
    return { valid: false, reason: "invalid_threshold", valid_signatures: 0 };
  }
  const message = Buffer.from(canonicalJSONStringify({ context: authorization.type, payload: authorization.payload }));
  const seen = new Set();
  let valid = 0;

  for (const item of authorization.signatures ?? []) {
    try {
      const publicKey = crypto.createPublicKey(item.public_key_pem);
      const fp = fingerprint(publicKey);
      if (fp !== item.key_fingerprint || seen.has(fp)) continue;
      const ok = crypto.verify(null, message, publicKey, Buffer.from(item.signature_base64, "base64"));
      if (ok) {
        seen.add(fp);
        valid += 1;
      }
    } catch {
      // Invalid signature/key material is counted as a failed signer.
    }
  }

  return {
    valid: valid >= authorization.threshold,
    reason: valid >= authorization.threshold ? null : "threshold_not_met",
    valid_signatures: valid,
    threshold: authorization.threshold
  };
}
