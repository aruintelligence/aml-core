function numericParts(version) {
  if (typeof version !== "string" || !/^\d+(?:\.\d+)*$/.test(version)) return null;
  return version.split(".").map((part) => Number(part));
}

export function compareProtocolVersions(left, right) {
  if (left === right) return 0;
  const leftParts = numericParts(left);
  const rightParts = numericParts(right);

  if (leftParts && rightParts) {
    const length = Math.max(leftParts.length, rightParts.length);
    for (let i = 0; i < length; i += 1) {
      const a = leftParts[i] ?? 0;
      const b = rightParts[i] ?? 0;
      if (a !== b) return a < b ? -1 : 1;
    }
    return left < right ? -1 : 1;
  }

  return left < right ? -1 : 1;
}

export function highestCommonProtocolVersion(localVersions = [], remoteVersions = []) {
  const remote = new Set(remoteVersions);
  const common = [...new Set(localVersions)].filter((version) => remote.has(version));
  common.sort(compareProtocolVersions);
  return { common, selected: common.at(-1) ?? null };
}
