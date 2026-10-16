// Receipt-only JSON subset. This does not change canonical JSON rules for
// other protocols that snapshot host objects before applying their contracts.
export function assertReceiptJSON(value) {
  const ancestors = new Set();

  function walk(item) {
    if (item === null || typeof item === "string" || typeof item === "boolean") return;
    if (typeof item === "number") {
      if (!Number.isFinite(item)) throw new TypeError("AML_CANONICAL_JSON_NON_FINITE_NUMBER");
      return;
    }
    if (!item || typeof item !== "object") {
      throw new TypeError("AML_CANONICAL_JSON_UNSUPPORTED_VALUE");
    }
    if (ancestors.has(item)) throw new TypeError("AML_CANONICAL_JSON_CYCLE");
    ancestors.add(item);
    try {
      if (Array.isArray(item)) {
        // JSON.stringify turns holes into null and ignores all non-index keys.
        if (Reflect.ownKeys(item).length !== item.length + 1) {
          throw new TypeError("AML_CANONICAL_JSON_NON_JSON_ARRAY");
        }
        for (let index = 0; index < item.length; index++) {
          const descriptor = Object.getOwnPropertyDescriptor(item, index);
          if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
            throw new TypeError("AML_CANONICAL_JSON_NON_JSON_ARRAY");
          }
          walk(descriptor.value);
        }
        return;
      }
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError("AML_CANONICAL_JSON_NON_PLAIN_OBJECT");
      }
      for (const key of Reflect.ownKeys(item)) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (typeof key !== "string" || !descriptor.enumerable || !("value" in descriptor)) {
          throw new TypeError("AML_CANONICAL_JSON_NON_JSON_OBJECT");
        }
        walk(descriptor.value);
      }
    } finally {
      ancestors.delete(item);
    }
  }

  walk(value);
}
