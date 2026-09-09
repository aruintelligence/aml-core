import crypto from "node:crypto";

import { tokenize } from "./lexer.js";
import { parse } from "./parser.js";
import { buildAMT } from "./amtBuilder.js";
import { canonicalJSONStringify } from "../protocol/canonicalJson.js";

const MATERIAL_PROTOCOL = "aml-meaning-material/1";

function sha256Utf8(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function sourceToAMT(source) {
  const tokens = tokenize(source);
  const ast = parse(tokens);
  return buildAMT(ast);
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

export function meaningFingerprint(source) {
  if (typeof source !== "string") throw new TypeError("AML source must be a string.");
  return fingerprintAMT(sourceToAMT(source));
}

export function compareMeaningFingerprints(leftSource, rightSource) {
  const left = meaningFingerprint(leftSource);
  const right = meaningFingerprint(rightSource);
  return {
    protocol: "aml-meaning-equivalence/1",
    version: "1.0",
    equivalent: left.fingerprint === right.fingerprint,
    left,
    right
  };
}
