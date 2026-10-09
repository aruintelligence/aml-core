export const DEFAULT_TRUSTED_CALLBACK_TIMEOUT_MS = 5000;

export function validateTrustedCallbackTimeout(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
  return value;
}

// The deadline bounds the HTTP request even if application code never settles.
// The signal lets a cooperative lookup cancel its own downstream work.
export async function runTrustedCallback(callback, req, timeoutMs) {
  const controller = new AbortController();
  let timer;
  let onAborted;
  const interrupted = new Promise((_, reject) => {
    onAborted = () => {
      controller.abort();
      reject(new Error("request_aborted"));
    };
    req.once?.("aborted", onAborted);
  });

  try {
    if (req.aborted) {
      controller.abort();
      throw new Error("request_aborted");
    }
    return await Promise.race([
      Promise.resolve().then(() => callback(req, { signal: controller.signal })),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error("trusted_callback_timeout"));
        }, timeoutMs);
      }),
      interrupted
    ]);
  } finally {
    clearTimeout(timer);
    req.off?.("aborted", onAborted);
  }
}
