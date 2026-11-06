function canonicalPrimitive(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("AML_CANONICAL_JSON_NON_FINITE_NUMBER");
    return value;
  }
  if (["undefined", "function", "symbol", "bigint"].includes(typeof value)) {
    throw new TypeError("AML_CANONICAL_JSON_UNSUPPORTED_VALUE");
  }
  return undefined;
}

export function canonicalize(value, { maxArrayLength = Infinity } = {}) {
  if (maxArrayLength !== Infinity &&
      (!Number.isSafeInteger(maxArrayLength) || maxArrayLength < 0)) {
    throw new TypeError("AML_CANONICAL_JSON_INVALID_LIMIT");
  }
  const ancestors = new Set();
  function walk(item) {
    const primitive = canonicalPrimitive(item);
    if (primitive !== undefined || item === null) return primitive;
    if (ancestors.has(item)) throw new TypeError("AML_CANONICAL_JSON_CYCLE");
    ancestors.add(item);
    try {
      if (Array.isArray(item)) {
        // Calling item.map lets an input-owned method or Symbol.species replace
        // the bytes being authorized. Keep the existing JSON.stringify projection
        // of holes and extra properties for this versioned canonicalization.
        const length = item.length;
        if (length > maxArrayLength) throw new TypeError("AML_CANONICAL_JSON_ARRAY_TOO_LARGE");
        const result = new Array(length);
        for (let i = 0; i < length; i++) {
          if (i in item) result[i] = walk(item[i]);
        }
        return result;
      }

      if (item && typeof item === "object") {
        const prototype = Object.getPrototypeOf(item);
        if (prototype !== Object.prototype && prototype !== null) {
          throw new TypeError("AML_CANONICAL_JSON_NON_PLAIN_OBJECT");
        }
        return Object.fromEntries(
          Object.keys(item).sort().map((key) => [key, walk(item[key])])
        );
      }

      throw new TypeError("AML_CANONICAL_JSON_UNSUPPORTED_VALUE");
    } finally {
      ancestors.delete(item);
    }
  }
  return walk(value);
}

export function canonicalJSONStringify(value, options) {
  // JSON.stringify invokes inherited toJSON hooks. The canonical copy must
  // not inherit hooks from a polluted Object or Array prototype. The public
  // canonicalize() result retains its existing ordinary-object API shape.
  function stripInheritedHooks(item) {
    if (item && typeof item === "object") {
      for (const child of Object.values(item)) stripInheritedHooks(child);
      Object.setPrototypeOf(item, null);
    }
    return item;
  }
  return JSON.stringify(stripInheritedHooks(canonicalize(value, options)));
}
