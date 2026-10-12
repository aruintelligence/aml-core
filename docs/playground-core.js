// Share links carry source in the URL fragment. No server or account is involved.
export const MAX_SHARED_SOURCE = 2400;
const MAX_FRAGMENT_LENGTH = 12000;

function validSource(source) {
  if (typeof source !== "string" || !source.trim() || source.length > MAX_SHARED_SOURCE) {
    throw new RangeError(`Shareable source must be 1–${MAX_SHARED_SOURCE} characters`);
  }
  return source;
}

export function playgroundShareUrl(source, pageUrl) {
  const url = new URL(pageUrl);
  const state = new URLSearchParams({ v: "1", source: validSource(source) });
  if (state.toString().length > MAX_FRAGMENT_LENGTH) throw new RangeError("Encoded source is too long to share");
  url.search = "";
  url.hash = state.toString();
  return url.href;
}

export function parsePlaygroundShare(pageUrl) {
  const hash = new URL(pageUrl).hash.slice(1);
  if (!hash || hash === "editor" || hash === "live-stage") return null;
  if (hash.length > MAX_FRAGMENT_LENGTH) throw new RangeError("Shared source is too long");
  const state = new URLSearchParams(hash);
  if (state.size !== 2 || state.getAll("v").length !== 1 ||
      state.getAll("source").length !== 1 || [...state.keys()].some(key => key !== "v" && key !== "source") ||
      state.get("v") !== "1") throw new RangeError("Invalid shared source link");
  return validSource(state.get("source"));
}
