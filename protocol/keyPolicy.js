// Signing-key algorithm policy for capability tokens and threshold
// authorizations (shared rule with independent/python/key_policy.py and
// independent/go/keypolicy.go; vectors in conformance/key-policy/).
//
// Ed25519 only. ECDSA (P-256 and other curves), RSA (PKCS#1 v1.5 and PSS),
// Ed448 and every other key type are refused, with or without a trust config.
// Reason: ECDSA signatures are malleable ((r, s) and (r, n - s) both verify),
// so a non-Ed25519 artifact can have more than one valid encoding of the same
// authorization; one algorithm also keeps every verifier's accepted set equal.
// Refusal is explicit: verifiers report AML_KEY_TYPE_NOT_ED25519 /
// "key_type_not_ed25519" and signers throw; nothing is silently skipped.
import crypto from "node:crypto";

export const AML_ALLOWED_SIGNATURE_KEY_TYPE = "ed25519";
export const AML_KEY_TYPE_NOT_ED25519 = "AML_KEY_TYPE_NOT_ED25519";

// True only for a KeyObject whose asymmetric type is exactly Ed25519.
export function isEd25519KeyObject(key) {
  return Boolean(key) && typeof key === "object" && key.asymmetricKeyType === AML_ALLOWED_SIGNATURE_KEY_TYPE;
}

// Private signing key for an AML signer, or throws AML_KEY_TYPE_NOT_ED25519.
export function requireEd25519PrivateKey(privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (!isEd25519KeyObject(privateKey)) {
    throw new Error(`${AML_KEY_TYPE_NOT_ED25519}: signing key type ${privateKey.asymmetricKeyType} is not accepted; use Ed25519`);
  }
  return privateKey;
}
