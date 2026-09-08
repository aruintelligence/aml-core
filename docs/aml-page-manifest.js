import { evaluateLiveAML, startAMLLiveGate } from './aml-live.js';

export function applyAMLPageManifest(manifest, root = document) {
  if (!manifest || manifest.schema !== 'aml-page/1' || !Array.isArray(manifest.elements)) {
    throw new Error('AML_PAGE_INVALID_MANIFEST');
  }

  const applied = [];
  for (const entry of manifest.elements) {
    if (!entry || typeof entry.selector !== 'string') continue;
    const nodes = [...root.querySelectorAll(entry.selector)];
    for (const node of nodes) {
      if (entry.purpose != null) node.dataset.amlPurpose = String(entry.purpose);
      if (entry.content != null) node.dataset.amlContent = String(entry.content);
      if (entry.attention_cost != null) node.dataset.amlAttentionCost = String(entry.attention_cost);
      if (entry.restoration_value != null) node.dataset.amlRestorationValue = String(entry.restoration_value);
      applied.push({ selector: entry.selector, id: node.id || null });
    }
  }

  const receipt = evaluateLiveAML('page-manifest');
  document.dispatchEvent(new CustomEvent('aml-page-manifest-applied', {
    detail: { schema: manifest.schema, applied, receipt }
  }));
  return { applied, receipt };
}

export function readEmbeddedAMLPageManifest(root = document) {
  const node = root.querySelector('script[type="application/aml+json"]');
  if (!node) return null;
  return JSON.parse(node.textContent || '{}');
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
