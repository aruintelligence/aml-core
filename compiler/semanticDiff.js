// compiler/semanticDiff.js
// ĀML v1.3 — semantic diffs over Abstract Meaning Trees.

import { compileSource } from "./compiler.js";
import { fingerprintAMT } from "./meaningFingerprint.js";

function flatten(nodes, parent = "root", out = new Map(), ordinal = { value: 0 }) {
  for (const node of nodes || []) {
    const key = node.identifier || node.name || `${parent}/${node.type}:${ordinal.value++}`;
    out.set(key, {
      key,
      type: node.type,
      name: node.name || null,
      identifier: node.identifier || null,
      properties: structuredClone(node.properties || {}),
      render_metadata: structuredClone(node.render_metadata || {})
    });
    flatten(node.children, key, out, ordinal);
  }
  return out;
}

function changedFields(left, right) {
  const keys = new Set([...Object.keys(left || {}), ...Object.keys(right || {})]);
  const changes = {};
  for (const key of keys) {
    const a = left?.[key];
    const b = right?.[key];
    if (JSON.stringify(a) !== JSON.stringify(b)) changes[key] = { before: a ?? null, after: b ?? null };
  }
  return changes;
}

export function semanticDiff(leftSource, rightSource, options = {}) {
  const timestamp = options.timestamp ?? "1970-01-01T00:00:00.000Z";
  const left = compileSource(leftSource, { timestamp, policy: options.policy, context: options.context || {} });
  const right = compileSource(rightSource, { timestamp, policy: options.policy, context: options.context || {} });
  const leftFingerprint = fingerprintAMT(left.amt);
  const rightFingerprint = fingerprintAMT(right.amt);
  const leftNodes = flatten(left.amt.root);
  const rightNodes = flatten(right.amt.root);
  const keys = [...new Set([...leftNodes.keys(), ...rightNodes.keys()])].sort();

  const added = [];
  const removed = [];
  const changed = [];
  const unchanged = [];

  for (const key of keys) {
    const a = leftNodes.get(key);
    const b = rightNodes.get(key);
    if (!a) { added.push(b); continue; }
    if (!b) { removed.push(a); continue; }

    const propertyChanges = changedFields(a.properties, b.properties);
    const meaningChanges = changedFields(a.render_metadata, b.render_metadata);
    const structuralChanges = changedFields(
      { type: a.type, name: a.name, identifier: a.identifier },
      { type: b.type, name: b.name, identifier: b.identifier }
    );

    if (Object.keys(propertyChanges).length || Object.keys(meaningChanges).length || Object.keys(structuralChanges).length) {
      changed.push({ key, structural_changes: structuralChanges, property_changes: propertyChanges, meaning_changes: meaningChanges });
    } else {
      unchanged.push(key);
    }
  }

  return {
    protocol: "ĀML Semantic Diff",
    version: "1.0",
    meaning_equivalent: leftFingerprint.fingerprint === rightFingerprint.fingerprint,
    left_meaning_fingerprint: leftFingerprint.fingerprint,
    right_meaning_fingerprint: rightFingerprint.fingerprint,
    fingerprint_protocol: leftFingerprint.protocol,
    summary: { added: added.length, removed: removed.length, changed: changed.length, unchanged: unchanged.length },
    added,
    removed,
    changed,
    unchanged
  };
}
