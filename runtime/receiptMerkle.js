// runtime/receiptMerkle.js
// ĀML v1.3 — Merkle batching for execution-receipt hashes.

import crypto from "node:crypto";

function hashPair(left, right) {
  return crypto.createHash("sha256").update(`${left}:${right}`).digest("hex");
}

function normalizeLeaf(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error("Merkle leaves must be SHA-256 hex strings.");
  }
  return value.toLowerCase();
}

export function buildReceiptMerkleTree(receiptHashes) {
  if (!Array.isArray(receiptHashes) || receiptHashes.length === 0) throw new Error("At least one receipt hash is required.");
  const leaves = receiptHashes.map(normalizeLeaf);
  const levels = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = current[i + 1] ?? left;
      next.push(hashPair(left, right));
    }
    levels.push(next);
    current = next;
  }
  return {
    protocol: "ĀML Receipt Merkle Batch",
    version: "1.0",
    leaf_count: leaves.length,
    root_sha256: current[0],
    leaves,
    levels
  };
}

export function createReceiptInclusionProof(tree, index) {
  if (!tree || tree.protocol !== "ĀML Receipt Merkle Batch") throw new Error("Invalid ĀML receipt Merkle tree.");
  if (!Number.isInteger(index) || index < 0 || index >= tree.leaf_count) throw new RangeError("Merkle proof index out of range.");
  const proof = [];
  let cursor = index;
  for (let levelIndex = 0; levelIndex < tree.levels.length - 1; levelIndex++) {
    const level = tree.levels[levelIndex];
    const siblingIndex = cursor % 2 === 0 ? cursor + 1 : cursor - 1;
    const sibling = level[siblingIndex] ?? level[cursor];
    proof.push({ position: cursor % 2 === 0 ? "right" : "left", hash: sibling });
    cursor = Math.floor(cursor / 2);
  }
  return {
    protocol: "ĀML Receipt Inclusion Proof",
    version: "1.0",
    leaf: tree.leaves[index],
    index,
    root_sha256: tree.root_sha256,
    proof
  };
}

export function verifyReceiptInclusionProof(inclusionProof) {
  if (!inclusionProof || inclusionProof.protocol !== "ĀML Receipt Inclusion Proof") {
    return { verified: false, reason: "invalid_protocol" };
  }
  if (inclusionProof.version !== "1.0") return { verified: false, reason: "unsupported_version" };
  if (!Number.isInteger(inclusionProof.index) || inclusionProof.index < 0) return { verified: false, reason: "invalid_index" };
  if (!Array.isArray(inclusionProof.proof)) return { verified: false, reason: "invalid_proof" };

  try {
    let current = normalizeLeaf(inclusionProof.leaf);
    const expectedRoot = normalizeLeaf(inclusionProof.root_sha256);
    let cursor = inclusionProof.index;

    for (const step of inclusionProof.proof) {
      if (!step || typeof step !== "object" || Array.isArray(step)) return { verified: false, reason: "invalid_step" };
      if (step.position !== "left" && step.position !== "right") return { verified: false, reason: "invalid_position" };

      const expectedPosition = cursor % 2 === 0 ? "right" : "left";
      if (step.position !== expectedPosition) return { verified: false, reason: "index_path_mismatch" };

      const sibling = normalizeLeaf(step.hash);
      current = step.position === "left"
        ? hashPair(sibling, current)
        : hashPair(current, sibling);
      cursor = Math.floor(cursor / 2);
    }

    return {
      verified: current === expectedRoot,
      reason: current === expectedRoot ? null : "root_mismatch",
      calculated_root_sha256: current,
      root_sha256: expectedRoot
    };
  } catch {
    return { verified: false, reason: "invalid_hash" };
  }
}
