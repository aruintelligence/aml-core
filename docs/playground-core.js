// Share links carry source in the URL fragment. No server or account is involved.
export const MAX_SHARED_SOURCE = 2400;
const MAX_FRAGMENT_LENGTH = 12000;

export function comparisonSample(restoration = 1) {
  if (!Number.isInteger(restoration) || restoration < 0 || restoration > 10)
    throw new RangeError("Comparison restoration must be an integer from 0 to 10");
  return `transmission "compare_two_prompts" {
  engram urgentOffer {
    value: "Buy before the timer expires"
    purpose: "Prompt an immediate purchase"
    attention_cost: 5
    restoration_value: ${restoration}
  }
  engram clearDetails {
    value: "Review the full terms"
    purpose: "Help compare the offer"
    attention_cost: 5
    restoration_value: 5
  }
}`;
}

// The dial owns only this exact sample. An edited program is never silently rewritten.
export function comparisonRestoration(source) {
  if (typeof source !== "string") return null;
  const match = source.match(/restoration_value: (10|[0-9])\n  }\n  engram clearDetails/);
  if (!match) return null;
  const restoration = Number(match[1]);
  return source === comparisonSample(restoration) ? restoration : null;
}

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
