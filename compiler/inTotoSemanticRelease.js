import { canonicalJSONStringify } from "../protocol/canonicalJson.js";
import { verifySemanticReleaseProof } from "./semanticReleaseProof.js";

export const IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1";
export const AML_SEMANTIC_RELEASE_PREDICATE_V1 = "https://aruintelligence.github.io/aml-core/predicates/semantic-release/v1.json";
export const AML_SEMANTIC_RELEASE_PREDICATE_SCHEMA_V1 = "aml-in-toto-semantic-release-predicate/1";

const CLAIM_BOUNDARY = "Verified AML semantic-transition integrity under aml-semantic-release-proof/1; not SLSA build provenance, certification, truth, safety, ethics, legal compliance, or institutional authority.";

function sameCanonical(a, b) {
  try {
    return canonicalJSONStringify(a) === canonicalJSONStringify(b);
  } catch {
    return false;
  }
}

function subjectName(proof) {
  const suffix = typeof proof.release_id === "string" && proof.release_id.length > 0
    ? proof.release_id
    : proof.after_manifest_root_sha256;
  return `aml-meaning-state:${suffix}`;
}

function derivedPredicate(proof, verification) {
  return {
    schema: AML_SEMANTIC_RELEASE_PREDICATE_SCHEMA_V1,
    releaseProof: structuredClone(proof),
    release: {
      id: proof.release_id ?? null,
      previousId: proof.previous_release_id ?? null
    },
    semantic: {
      beforeRootSha256: proof.before_manifest_root_sha256,
      afterRootSha256: proof.after_manifest_root_sha256,
      changed: proof.semantic_changed,
      lineageHeadSha256: proof.lineage_head_sha256,
      changeSummary: structuredClone(proof.change_summary)
    },
    attribution: {
      signer: verification.signer,
      generatedAt: verification.generated_at,
      publicKeySha256: proof.public_key_sha256,
      proofSha256: proof.proof_sha256
    },
    claimBoundary: CLAIM_BOUNDARY
  };
}

export function createInTotoSemanticReleaseStatement(proof) {
  const verification = verifySemanticReleaseProof(proof);
  if (!verification.verified || !verification.attribution_bound) {
    throw new Error("in-toto semantic release statement requires a fully verified attributed AML Semantic Release Proof.");
  }

  return {
    _type: IN_TOTO_STATEMENT_V1,
    subject: [{
      name: subjectName(proof),
      digest: { sha256: proof.after_manifest_root_sha256 }
    }],
    predicateType: AML_SEMANTIC_RELEASE_PREDICATE_V1,
    predicate: derivedPredicate(proof, verification)
  };
}

export function verifyInTotoSemanticReleaseStatement(statement) {
  const base = {
    verified: false,
    statement_contract_valid: false,
    subject_binding_valid: false,
    predicate_binding_valid: false,
    release_proof_valid: false,
    attribution_bound: false,
    signer: null,
    release_id: null,
    before_manifest_root_sha256: null,
    after_manifest_root_sha256: null,
    lineage_head_sha256: null,
    semantic_changed: null,
    change_summary: null,
    proof_sha256: null,
    reason: null
  };

  try {
    if (!statement || typeof statement !== "object" || Array.isArray(statement)) {
      return { ...base, reason: "invalid_statement" };
    }
    if (statement._type !== IN_TOTO_STATEMENT_V1 || statement.predicateType !== AML_SEMANTIC_RELEASE_PREDICATE_V1) {
      return { ...base, reason: "invalid_statement_contract" };
    }
    if (!Array.isArray(statement.subject) || statement.subject.length !== 1 || !statement.predicate || typeof statement.predicate !== "object" || Array.isArray(statement.predicate)) {
      return { ...base, reason: "invalid_statement_structure" };
    }
    if (statement.predicate.schema !== AML_SEMANTIC_RELEASE_PREDICATE_SCHEMA_V1) {
      return { ...base, reason: "invalid_predicate_schema" };
    }

    const proof = statement.predicate.releaseProof;
    const proofVerification = verifySemanticReleaseProof(proof);
    if (!proofVerification.verified || !proofVerification.attribution_bound) {
      return { ...base, statement_contract_valid: true, reason: "invalid_release_proof" };
    }

    const expected = createInTotoSemanticReleaseStatement(proof);
    const subjectValid = sameCanonical(statement.subject, expected.subject);
    const predicateValid = (
      sameCanonical(statement.predicate.release, expected.predicate.release) &&
      sameCanonical(statement.predicate.semantic, expected.predicate.semantic) &&
      sameCanonical(statement.predicate.attribution, expected.predicate.attribution) &&
      statement.predicate.claimBoundary === expected.predicate.claimBoundary
    );
    const verified = subjectValid && predicateValid;

    return {
      ...base,
      verified,
      statement_contract_valid: true,
      subject_binding_valid: subjectValid,
      predicate_binding_valid: predicateValid,
      release_proof_valid: true,
      attribution_bound: verified,
      signer: verified ? proofVerification.signer : null,
      release_id: proof.release_id ?? null,
      before_manifest_root_sha256: proof.before_manifest_root_sha256,
      after_manifest_root_sha256: proof.after_manifest_root_sha256,
      lineage_head_sha256: proof.lineage_head_sha256,
      semantic_changed: proof.semantic_changed,
      change_summary: structuredClone(proof.change_summary),
      proof_sha256: proof.proof_sha256,
      reason: verified ? null : !subjectValid ? "subject_binding_mismatch" : "predicate_binding_mismatch"
    };
  } catch {
    return { ...base, reason: "statement_verification_error" };
  }
}
