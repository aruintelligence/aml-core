function prepare(items, baseKeyFor) {
  if (!Array.isArray(items)) throw new TypeError("Comparison items must be an array.");
  if (typeof baseKeyFor !== "function") throw new TypeError("Comparison key resolver must be a function.");
  return items.map((item, index) => {
    const raw = baseKeyFor(item, index);
    const baseKey = typeof raw === "string" && raw.length > 0 ? raw : `index:${index}`;
    return { item, index, baseKey };
  });
}

function totalsFor(prepared) {
  const totals = new Map();
  for (const entry of prepared) totals.set(entry.baseKey, (totals.get(entry.baseKey) || 0) + 1);
  return totals;
}

function ambiguousFromTotals(totals) {
  return [...totals.entries()]
    .filter(([, count]) => count > 1)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => a.key.localeCompare(b.key));
}

function buildPreparedIndex(prepared, forcedAmbiguous = new Set()) {
  const totals = totalsFor(prepared);
  const seen = new Map();
  const index = new Map();
  const entries = [];

  for (const entry of prepared) {
    const total = totals.get(entry.baseKey);
    const occurrence = (seen.get(entry.baseKey) || 0) + 1;
    seen.set(entry.baseKey, occurrence);
    const ambiguous = total > 1 || forcedAmbiguous.has(entry.baseKey);
    const key = ambiguous ? `${entry.baseKey}#${occurrence}` : entry.baseKey;
    const indexed = {
      key,
      base_key: entry.baseKey,
      occurrence,
      ambiguous,
      item: entry.item,
      index: entry.index
    };
    entries.push(indexed);
    index.set(key, entry.item);
  }

  return { index, entries, ambiguous_identity_keys: ambiguousFromTotals(totals) };
}

export function buildComparisonIndex(items, baseKeyFor, options = {}) {
  const prepared = prepare(items, baseKeyFor);
  return buildPreparedIndex(prepared, new Set(options.force_ambiguous_keys || []));
}

export function buildPairedComparisonIndexes(leftItems, rightItems, baseKeyFor) {
  const leftPrepared = prepare(leftItems, baseKeyFor);
  const rightPrepared = prepare(rightItems, baseKeyFor);
  const leftTotals = totalsFor(leftPrepared);
  const rightTotals = totalsFor(rightPrepared);
  const forced = new Set();

  for (const [key, count] of leftTotals) if (count > 1) forced.add(key);
  for (const [key, count] of rightTotals) if (count > 1) forced.add(key);

  const left = buildPreparedIndex(leftPrepared, forced);
  const right = buildPreparedIndex(rightPrepared, forced);
  return {
    left,
    right,
    ambiguous_identity_keys: mergeAmbiguousIdentityKeys(
      ambiguousFromTotals(leftTotals),
      ambiguousFromTotals(rightTotals)
    )
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
