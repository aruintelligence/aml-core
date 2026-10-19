// JSON.parse accepts duplicate object names with last-key-wins semantics.
// Signed evidence must not depend on a parser's choice of first or last.
// Parse syntax with the platform parser, then scan the same source for names.
export function parseJsonWithoutDuplicateKeys(source, { integerNumbersOnly = false } = {}) {
  const parsed = JSON.parse(source);
  const frames = [];
  const numberToken = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === '"') {
      const start = index;
      for (index += 1; index < source.length; index += 1) {
        if (source[index] === "\\") index += 1;
        else if (source[index] === '"') break;
      }
      const frame = frames[frames.length - 1];
      if (frame?.kind === "object" && frame.nextIsKey) {
        // Decoding the exact quoted token catches escaped aliases such as
        // "allowed" and "\u0061llowed" within the same object.
        const key = JSON.parse(source.slice(start, index + 1));
        if (frame.keys.has(key)) {
          throw Object.assign(new SyntaxError("duplicate JSON object key"), { code: "AML_DUPLICATE_JSON_KEY" });
        }
        frame.keys.add(key);
        frame.nextIsKey = false;
      }
    } else if (integerNumbersOnly && (char === "-" || (char >= "0" && char <= "9"))) {
      numberToken.lastIndex = index;
      const token = numberToken.exec(source)[0];
      if (/[.eE]/.test(token) || !Number.isSafeInteger(Number(token))) {
        throw Object.assign(new SyntaxError("nonportable JSON number"),
          { code: "AML_NON_PORTABLE_JSON_NUMBER" });
      }
      index += token.length - 1;
    } else if (char === "{") {
      frames.push({ kind: "object", keys: new Set(), nextIsKey: true });
    } else if (char === "[") {
      frames.push({ kind: "array" });
    } else if (char === "}" || char === "]") {
      frames.pop();
    } else if (char === "," && frames[frames.length - 1]?.kind === "object") {
      frames[frames.length - 1].nextIsKey = true;
    }
  }
  return parsed;
}
