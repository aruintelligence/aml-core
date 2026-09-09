// runtime/decisionCache.js
// Small bounded in-memory cache for AML deployment evaluation.
// This is a process-local optimization, not a distributed cache or freshness authority.

function assertPositiveInteger(value, name) {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer.`);
  }
}

export function createDecisionCache(options = {}) {
  const maxEntries = options.max_entries ?? 256;
  const ttlMs = options.ttl_ms ?? 30_000;
  assertPositiveInteger(maxEntries, "max_entries");
  assertPositiveInteger(ttlMs, "ttl_ms");

  const entries = new Map();
  const stats = { hits: 0, misses: 0, sets: 0, evictions: 0 };

  function pruneExpired(now = Date.now()) {
    for (const [key, entry] of entries) {
      if (entry.expires_at_ms <= now) entries.delete(key);
    }
  }

  function evictOldest() {
    if (entries.size < maxEntries) return;
    const oldestKey = entries.keys().next().value;
    if (oldestKey !== undefined) {
      entries.delete(oldestKey);
      stats.evictions += 1;
    }
  }

  return {
    protocol: "ĀML Decision Cache",
    version: "1.0",
    max_entries: maxEntries,
    ttl_ms: ttlMs,
    get(key, now = Date.now()) {
      pruneExpired(now);
      const entry = entries.get(key);
      if (!entry) {
        stats.misses += 1;
        return null;
      }
      // Refresh insertion order to approximate LRU behavior.
      entries.delete(key);
      entries.set(key, entry);
      stats.hits += 1;
      return structuredClone(entry.value);
    },
    set(key, value, now = Date.now()) {
      pruneExpired(now);
      if (entries.has(key)) entries.delete(key);
      evictOldest();
      entries.set(key, {
        value: structuredClone(value),
        created_at_ms: now,
        expires_at_ms: now + ttlMs
      });
      stats.sets += 1;
      return key;
    },
    delete(key) {
      return entries.delete(key);
    },
    clear() {
      entries.clear();
    },
    stats() {
      pruneExpired();
      return {
        ...stats,
        size: entries.size,
        max_entries: maxEntries,
        ttl_ms: ttlMs
      };
    }
  };
}
