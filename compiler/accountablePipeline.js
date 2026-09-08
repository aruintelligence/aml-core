// compiler/accountablePipeline.js
// ĀML v1.2 — end-to-end accountable AI intent execution pipeline.

import crypto from "node:crypto";
import { generateAMLFromIntent } from "./intentCompiler.js";
import { compileSource } from "./compiler.js";
import { simulatePolicies } from "./policySimulator.js";
import { policyFromProfile } from "../runtime/policyComposition.js";
import { resolvePolicyProfile } from "../runtime/policyProfiles.js";

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().filter(key => value[key] !== undefined).map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : stableStringify(value)).digest("hex");
}

function receiptPayload(receipt) {
  const { receipt_sha256, signature, ...payload } = receipt;
  return payload;
}

export function executeAccountableIntent(intent, options = {}) {
  const timestamp = options.timestamp ?? new Date().toISOString();
  const profile = resolvePolicyProfile(options.profile || "calm_default");
  const context = options.context || {};
  const amlSource = generateAMLFromIntent(intent);

  const simulations = simulatePolicies(amlSource, profile.policies, {
    timestamp,
    context
  });

  const composedPolicy = policyFromProfile(profile);
  const selectedCompilation = compileSource(amlSource, {
    timestamp,
    policy: composedPolicy,
    context
  });

  const receipt = {
    protocol: "ĀML Accountable Execution Receipt",
    version: "1.0",
    timestamp,
    profile: {
      id: profile.id,
      description: profile.description,
      policies: profile.policies
    },
    context: structuredClone(context),
    intent_sha256: sha256(intent),
    aml_sha256: sha256(amlSource),
    simulation_sha256: sha256(simulations),
    output_sha256: sha256(selectedCompilation.html),
    decision_sha256: sha256(selectedCompilation.renderDecisions),
    intent: structuredClone(intent),
    aml_source: amlSource,
    simulations,
    selected_render: {
      policy_id: composedPolicy.id,
      allowed: selectedCompilation.renderDecisions.filter(item => item.render_allowed).length,
      suppressed: selectedCompilation.renderDecisions.filter(item => !item.render_allowed).length,
      decisions: selectedCompilation.renderDecisions,
      html: selectedCompilation.html
    }
  };

  receipt.receipt_sha256 = sha256(receiptPayload(receipt));
  return receipt;
}

export function verifyExecutionReceipt(receipt) {
  if (!receipt || receipt.protocol !== "ĀML Accountable Execution Receipt") {
    throw new Error("Invalid ĀML accountable execution receipt.");
  }

  const expected = sha256(receiptPayload(receipt));
  return {
    verified: expected === receipt.receipt_sha256,
    expected_sha256: expected,
    receipt_sha256: receipt.receipt_sha256
  };
}

export function signExecutionReceipt(receipt, privateKeyPem, options = {}) {
  const integrity = verifyExecutionReceipt(receipt);
  if (!integrity.verified) throw new Error("Cannot sign a mutated or invalid ĀML execution receipt.");

  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const signature = crypto.sign(null, Buffer.from(receipt.receipt_sha256, "utf8"), privateKey);

  return {
    ...receipt,
    signature: {
      protocol: "ĀML Execution Receipt Attestation",
      version: "1.0",
      algorithm: "Ed25519",
      signer: options.signer ?? null,
      signed_at: options.timestamp ?? new Date().toISOString(),
      public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      public_key_sha256: sha256(publicKeyDer),
      signature_base64: signature.toString("base64")
    }
  };
}

export function verifySignedExecutionReceipt(receipt) {
  const integrity = verifyExecutionReceipt(receipt);
  if (!integrity.verified || !receipt.signature) {
    return { verified: false, integrity_valid: integrity.verified, signature_valid: false };
  }

  const publicKey = crypto.createPublicKey(receipt.signature.public_key_pem);
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const fingerprintValid = sha256(publicKeyDer) === receipt.signature.public_key_sha256;
  const signatureValid = crypto.verify(
    null,
    Buffer.from(receipt.receipt_sha256, "utf8"),
    publicKey,
    Buffer.from(receipt.signature.signature_base64, "base64")
  );

  return {
    verified: integrity.verified && fingerprintValid && signatureValid,
    integrity_valid: integrity.verified,
    signature_valid: signatureValid,
    public_key_fingerprint_valid: fingerprintValid,
    signer: receipt.signature.signer ?? null,
    signed_at: receipt.signature.signed_at ?? null
  };
}
