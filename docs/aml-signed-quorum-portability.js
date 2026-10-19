// Check the JSON value domain that the project-authored Python verifier can
// reproduce under sorted-json-v1. The ordinary JS verifier keeps its existing
// wider domain; callers opt into this gate for cross-runtime decisions.
const isArrayIndex = key => key.length <= 10 && /^(0|[1-9][0-9]*)$/.test(key) &&
  Number(key) < 4294967295;

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (++index === value.length || value.charCodeAt(index) < 0xdc00 ||
          value.charCodeAt(index) > 0xdfff) return true;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

const pointer = (path, key) => `${path}/${String(key).replace(/~/g, '~0').replace(/\//g, '~1')}`;

export function signedQuorumPortabilityIssue(value) {
  function visit(item, path) {
    if (typeof item === 'number') return Number.isSafeInteger(item) ? null :
      { path, reason: 'unsafe_or_fractional_number' };
    if (typeof item === 'string') return hasUnpairedSurrogate(item) ?
      { path, reason: 'unpaired_surrogate' } : null;
    if (item === null || typeof item === 'boolean') return null;
    if (Array.isArray(item)) {
      for (let index = 0; index < item.length; index++) {
        const issue = visit(item[index], pointer(path, index));
        if (issue) return issue;
      }
      return null;
    }
    if (item && typeof item === 'object') {
      for (const key of Object.keys(item)) {
        if ([...key].some(char => char.codePointAt(0) > 0xffff) ||
            hasUnpairedSurrogate(key) || isArrayIndex(key)) {
          return { path: pointer(path, key), reason: 'nonportable_object_key' };
        }
        const issue = visit(item[key], pointer(path, key));
        if (issue) return issue;
      }
      return null;
    }
    return { path, reason: 'unsupported_json_value' };
  }
  return visit(value, '');
}
