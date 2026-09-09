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

  if (Array.isArray(value)) return value.map(canonicalize);

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
  return JSON.stringify(canonicalize(value));
}
