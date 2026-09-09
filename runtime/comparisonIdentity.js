export function buildComparisonIndex(items, baseKeyFor) {
  if (!Array.isArray(items)) throw new TypeError("Comparison items must be an array.");
  if (typeof baseKeyFor !== "function") throw new TypeError("Comparison key resolver must be a function.");

  const prepared = items.map((item, index) => {
    const raw = baseKeyFor(item, index);
    const baseKey = typeof raw === "string" && raw.length > 0 ? raw : `index:${index}`;
    return { item, index, baseKey };
  });

  const totals = new Map();
  for (const entry of prepared) totals.set(entry.baseKey, (totals.get(entry.baseKey) || 0) + 1);

  const seen = new Map();
  const index = new Map();
  const entries = [];
  for (const entry of prepared) {
    const total = totals.get(entry.baseKey);
    const occurrence = (seen.get(entry.baseKey) || 0) + 1;
    seen.set(entry.baseKey, occurrence);
    const key = total > 1 ? `${entry.baseKey}#${occurrence}` : entry.baseKey;
    const indexed = {
      key,
      base_key: entry.baseKey,
      occurrence,
      ambiguous: total > 1,
      item: entry.item,
      index: entry.index
    };
    entries.push(indexed);
    index.set(key, entry.item);
  }

  return {
    index,
    entries,
    ambiguous_identity_keys: [...totals.entries()]
      .filter(([, count]) => count > 1)
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => a.key.localeCompare(b.key))
  };
}

export function mergeAmbiguousIdentityKeys(...groups) {
  const counts = new Map();
  for (const group of groups) {
    for (const entry of group || []) {
      counts.set(entry.key, Math.max(counts.get(entry.key) || 0, entry.count));
    }
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => a.key.localeCompare(b.key));
}
