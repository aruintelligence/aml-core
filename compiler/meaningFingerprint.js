import crypto from "node:crypto";

import { compileSource } from "./compiler.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const MATERIAL_PROTOCOL = "aml-meaning-material/1";

function sha256Utf8(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

export function fingerprintAMT(amt) {
  if (!amt || amt.type !== "AbstractMeaningTree" || !Array.isArray(amt.root)) {
    throw new TypeError("AML meaning fingerprint requires an Abstract Meaning Tree.");
  }

  const material = {
    protocol: MATERIAL_PROTOCOL,
    amt
  };
  const canonical = canonicalJSONStringify(material);

  return {
    protocol: "aml-meaning-fingerprint/1",
    version: "1.0",
    algorithm: "sha256",
    material_protocol: MATERIAL_PROTOCOL,
    amt_version: amt.version ?? null,
    fingerprint: sha256Utf8(canonical)
  };
}

export function meaningFingerprint(source, options = {}) {
  if (typeof source !== "string") throw new TypeError("AML source must be a string.");
  const timestamp = options.timestamp ?? "1970-01-01T00:00:00.000Z";
  const compiled = compileSource(source, {
    timestamp,
    policy: options.policy,
    context: options.context || {}
  });
  return fingerprintAMT(compiled.amt);
}

export function compareMeaningFingerprints(leftSource, rightSource, options = {}) {
  const left = meaningFingerprint(leftSource, options);
  const right = meaningFingerprint(rightSource, options);
  return {
    protocol: "aml-meaning-equivalence/1",
    version: "1.0",
    equivalent: left.fingerprint === right.fingerprint,
    left,
    right
  };
}
