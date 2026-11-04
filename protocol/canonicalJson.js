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

export function canonicalize(value) {
  const primitive = canonicalPrimitive(value);
  if (primitive !== undefined || value === null) return primitive;

  if (Array.isArray(value)) {
    // Calling value.map lets an input-owned method or Symbol.species replace
    // the bytes being authorized. Keep the existing JSON.stringify projection
    // of holes and extra properties for this versioned canonicalization.
    const length = value.length;
    const result = new Array(length);
    for (let i = 0; i < length; i++) {
      if (i in value) result[i] = canonicalize(value[i]);
    }
    return result;
  }

  if (value && typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("AML_CANONICAL_JSON_NON_PLAIN_OBJECT");
    }
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])])
    );
  }

  throw new TypeError("AML_CANONICAL_JSON_UNSUPPORTED_VALUE");
}

export function canonicalJSONStringify(value) {
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
  return JSON.stringify(stripInheritedHooks(canonicalize(value)));
}
