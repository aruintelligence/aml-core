import { tokenize, parse, buildAMT } from "./aml-browser.js";
import { canonicalJSONStringifyBrowser, sha256Browser } from "./aml-browser-integrity.js";

const MATERIAL_PROTOCOL = "aml-meaning-material/1";

export async function fingerprintAMTBrowser(amt) {
  if (!amt || amt.type !== "AbstractMeaningTree" || !Array.isArray(amt.root)) {
    throw new TypeError("AML meaning fingerprint requires an Abstract Meaning Tree.");
  }
  const material = { protocol: MATERIAL_PROTOCOL, amt };
  const canonical = canonicalJSONStringifyBrowser(material);
  const fingerprint = await sha256Browser(canonical);
  return {
    protocol: "aml-meaning-fingerprint/1",
    version: "1.0",
    algorithm: "sha256",
    material_protocol: MATERIAL_PROTOCOL,
    amt_version: amt.version ?? null,
    fingerprint
  };
}

export async function meaningFingerprintBrowser(source) {
  if (typeof source !== "string") throw new TypeError("AML source must be a string.");
  return fingerprintAMTBrowser(buildAMT(parse(tokenize(source))));
}

export async function compareMeaningFingerprintsBrowser(leftSource, rightSource) {
  const [left, right] = await Promise.all([
    meaningFingerprintBrowser(leftSource),
    meaningFingerprintBrowser(rightSource)
  ]);
  return {
    protocol: "aml-meaning-equivalence/1",
    version: "1.0",
    equivalent: left.fingerprint === right.fingerprint,
    left,
    right
  };
}
