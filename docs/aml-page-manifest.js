import { evaluateLiveAML, startAMLLiveGate } from './aml-live.js';

const MAX_ENTRIES = 100;
const MAX_TOTAL_MATCHES = 1000;

function validScore(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 && number <= 10;
}

export function applyAMLPageManifest(manifest, root = document) {
  if (!manifest || manifest.schema !== 'aml-page/1' || !Array.isArray(manifest.elements)) {
    throw new Error('AML_PAGE_INVALID_MANIFEST');
  }
  if (manifest.elements.length > MAX_ENTRIES) {
    throw new Error('AML_PAGE_TOO_MANY_ENTRIES');
  }

  const applied = [];
  const errors = [];
  let totalMatches = 0;

  for (const [entryIndex, entry] of manifest.elements.entries()) {
    if (!entry || typeof entry.selector !== 'string' || !entry.selector.trim()) {
      errors.push({ entry: entryIndex, error: 'AML_PAGE_INVALID_SELECTOR' });
      continue;
    }
    if (!validScore(entry.attention_cost) || !validScore(entry.restoration_value)) {
      errors.push({ entry: entryIndex, selector: entry.selector, error: 'AML_PAGE_INVALID_SCORE' });
      continue;
    }

    let nodes;
    try {
      nodes = [...root.querySelectorAll(entry.selector)];
    } catch {
      errors.push({ entry: entryIndex, selector: entry.selector, error: 'AML_PAGE_INVALID_SELECTOR' });
      continue;
    }

    if (totalMatches + nodes.length > MAX_TOTAL_MATCHES) {
      errors.push({ entry: entryIndex, selector: entry.selector, error: 'AML_PAGE_MATCH_LIMIT' });
      break;
    }
    totalMatches += nodes.length;

    for (const node of nodes) {
      if (entry.purpose != null) node.dataset.amlPurpose = String(entry.purpose);
      if (entry.content != null) node.dataset.amlContent = String(entry.content);
      node.dataset.amlAttentionCost = String(entry.attention_cost);
      node.dataset.amlRestorationValue = String(entry.restoration_value);
      applied.push({ selector: entry.selector, id: node.id || null });
    }
  }

  const receipt = evaluateLiveAML('page-manifest');
  const detail = {
    schema: manifest.schema,
    limits: { max_entries: MAX_ENTRIES, max_total_matches: MAX_TOTAL_MATCHES },
    applied,
    errors,
    receipt
  };
  document.dispatchEvent(new CustomEvent('aml-page-manifest-applied', { detail }));
  return detail;
}

export function readEmbeddedAMLPageManifest(root = document) {
  const node = root.querySelector('script[type="application/aml+json"]');
  if (!node) return null;
  try {
    return JSON.parse(node.textContent || '{}');
  } catch {
    throw new Error('AML_PAGE_INVALID_JSON');
  }
}

export function startAMLPageManifest() {
  startAMLLiveGate();
  const manifest = readEmbeddedAMLPageManifest(document);
  if (!manifest) return null;
  return applyAMLPageManifest(manifest, document);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => startAMLPageManifest(), { once: true });
} else {
  startAMLPageManifest();
}
