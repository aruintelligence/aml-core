// runtime/accessibilityAudit.js
// ĀML v1.3 — declarative accessibility audit for meaning-bearing nodes.

function isTrue(value) {
  return value === true || value === "true" || value === "yes" || value === "required";
}

function isFalse(value) {
  return value === false || value === "false" || value === "no";
}

export function auditAccessibilityNode(node, context = {}) {
  const properties = node?.properties || {};
  const checks = [];

  if (context.prefers_reduced_motion === true && isTrue(properties.motion_required)) {
    const ok = isTrue(properties.reduced_motion_alternative);
    checks.push({
      id: "AML_A11Y_MOTION",
      ok,
      severity: ok ? "info" : "error",
      message: ok ? "Reduced-motion alternative declared." : "Motion-required node lacks reduced_motion_alternative."
    });
  }

  if (context.high_contrast_required === true) {
    const ok = !isFalse(properties.contrast_safe);
    checks.push({
      id: "AML_A11Y_CONTRAST",
      ok,
      severity: ok ? "info" : "error",
      message: ok ? "No explicit contrast-safety failure declared." : "Node declares contrast_safe=false."
    });
  }

  if (isTrue(properties.interactive) || isTrue(properties.requires_interaction)) {
    const ok = isTrue(properties.keyboard_accessible);
    checks.push({
      id: "AML_A11Y_KEYBOARD",
      ok,
      severity: ok ? "info" : "error",
      message: ok ? "Keyboard accessibility declared." : "Interactive node lacks keyboard_accessible=true."
    });
  }

  if (isTrue(properties.visual_only) || isTrue(properties.image_content)) {
    const alt = properties.text_alternative;
    const ok = typeof alt === "string" && alt.trim().length > 0;
    checks.push({
      id: "AML_A11Y_TEXT_ALT",
      ok,
      severity: ok ? "info" : "error",
      message: ok ? "Text alternative declared." : "Visual-only content lacks text_alternative."
    });
  }

  if (typeof context.max_cognitive_load === "number" && typeof properties.cognitive_load === "number") {
    const ok = properties.cognitive_load <= context.max_cognitive_load;
    checks.push({
      id: "AML_A11Y_COGNITIVE_LOAD",
      ok,
      severity: ok ? "info" : "warning",
      message: ok
        ? "Declared cognitive load is within runtime maximum."
        : `cognitive_load (${properties.cognitive_load}) exceeds max_cognitive_load (${context.max_cognitive_load}).`
    });
  }

  return {
    protocol: "ĀML Accessibility Audit",
    version: "1.0",
    identifier: node?.identifier || node?.name || null,
    passed: checks.every(check => check.ok),
    checks
  };
}

export function auditAccessibilityTree(amt, context = {}) {
  const audits = [];
  const walk = nodes => {
    for (const node of nodes || []) {
      if (node.properties) audits.push(auditAccessibilityNode(node, context));
      walk(node.children);
    }
  };
  walk(amt?.root || []);
  return {
    protocol: "ĀML Accessibility Audit Report",
    version: "1.0",
    nodes_audited: audits.length,
    failing_nodes: audits.filter(audit => !audit.passed).length,
    passed: audits.every(audit => audit.passed),
    audits
  };
}
