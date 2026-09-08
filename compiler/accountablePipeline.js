// compiler/accountablePipeline.js
// ĀML v1.3 — end-to-end accountable AI intent execution pipeline.

import crypto from "node:crypto";
import { generateAMLFromIntent } from "./intentCompiler.js";
import { compileSource } from "./compiler.js";
import { simulatePolicies } from "./policySimulator.js";
import { generateHTML } from "./htmlGenerator.js";
import { policyFromProfile } from "../runtime/policyComposition.js";
import { resolvePolicyProfile } from "../runtime/policyProfiles.js";
import { createAuditStream, appendAuditEvent, verifyAuditStream } from "../runtime/auditStream.js";
import { enforceCumulativeAttentionBudget } from "../runtime/attentionLedger.js";

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

function resolveInitialAttentionBudget(context) {
  if (typeof context.attention_budget_remaining === "number" && Number.isFinite(context.attention_budget_remaining)) {
    return context.attention_budget_remaining;
  }
  if (typeof context.attention_budget_initial === "number" && Number.isFinite(context.attention_budget_initial)) {
    return context.attention_budget_initial;
  }
  return Infinity;
}

export function executeAccountableIntent(intent, options = {}) {
  const timestamp = options.timestamp ?? new Date().toISOString();
  const profile = resolvePolicyProfile(options.profile || "calm_default");
  const context = options.context || {};
  const amlSource = generateAMLFromIntent(intent);
  const streamId = options.stream_id || sha256({ intent, profile: profile.id, timestamp }).slice(0, 32);
  const auditStream = createAuditStream({ stream_id: streamId, timestamp });

  appendAuditEvent(auditStream, {
    event_type: "intent_received",
    payload: { intent_sha256: sha256(intent), profile_id: profile.id }
  }, { timestamp });

  appendAuditEvent(auditStream, {
    event_type: "aml_generated",
    payload: { aml_sha256: sha256(amlSource) }
  }, { timestamp });

  const simulations = simulatePolicies(amlSource, profile.policies, {
    timestamp,
    context
  });

  appendAuditEvent(auditStream, {
    event_type: "policy_simulated",
    payload: { simulation_sha256: sha256(simulations), policies: profile.policies }
  }, { timestamp });

  const composedPolicy = policyFromProfile(profile);
  const selectedCompilation = compileSource(amlSource, {
    timestamp,
    policy: composedPolicy,
    context
  });

  const initialBudget = resolveInitialAttentionBudget(context);
  const cumulative = enforceCumulativeAttentionBudget(
    selectedCompilation.renderDecisions,
    initialBudget,
    { session_id: context.session_id || null }
  );

  const finalDecisions = cumulative.decisions;
  const finalHtml = generateHTML(selectedCompilation.amt, finalDecisions);

  appendAuditEvent(auditStream, {
    event_type: "policy_selected",
    payload: {
      policy_id: composedPolicy.id,
      decision_sha256: sha256(finalDecisions),
      attention_ledger_remaining: cumulative.ledger.remaining,
      attention_ledger_consumed: cumulative.ledger.consumed
    }
  }, { timestamp });

  appendAuditEvent(auditStream, {
    event_type: "output_rendered",
    payload: { output_sha256: sha256(finalHtml) }
  }, { timestamp });

  const auditVerification = verifyAuditStream(auditStream);

  const receipt = {
    protocol: "ĀML Accountable Execution Receipt",
    version: "1.1",
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
    output_sha256: sha256(finalHtml),
    decision_sha256: sha256(finalDecisions),
    audit_stream_sha256: sha256(auditStream),
    attention_ledger_sha256: sha256(cumulative.ledger),
    intent: structuredClone(intent),
    aml_source: amlSource,
    simulations,
    runtime_audit_stream: auditStream,
    runtime_audit_verified: auditVerification.verified,
    attention_ledger: cumulative.ledger,
    selected_render: {
      policy_id: composedPolicy.id,
      allowed: finalDecisions.filter(item => item.render_allowed).length,
      suppressed: finalDecisions.filter(item => !item.render_allowed).length,
      decisions: finalDecisions,
      html: finalHtml
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
  const audit = receipt.runtime_audit_stream ? verifyAuditStream(receipt.runtime_audit_stream) : { verified: true };
  const auditHashValid = receipt.runtime_audit_stream
    ? sha256(receipt.runtime_audit_stream) === receipt.audit_stream_sha256
    : true;
  const ledgerHashValid = receipt.attention_ledger
    ? sha256(receipt.attention_ledger) === receipt.attention_ledger_sha256
    : true;

  return {
    verified: expected === receipt.receipt_sha256 && audit.verified && auditHashValid && ledgerHashValid,
    receipt_hash_valid: expected === receipt.receipt_sha256,
    audit_stream_valid: audit.verified && auditHashValid,
    attention_ledger_valid: ledgerHashValid,
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
