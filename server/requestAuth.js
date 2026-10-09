import crypto from "node:crypto";

const error = (message, statusCode) => Object.assign(new Error(message), { statusCode });

// Shared, opt-in ingress guard. A callback can delegate identity to an
// application's trusted authentication layer; a bearer token is for bounded
// local or reverse-proxy deployments, never a replacement for transport TLS.
export function createRequestAuthenticator(config) {
  if (config == null) return null;

  if (typeof config === "function") {
    return async (req) => {
      let allowed;
      try {
        allowed = await config(req);
      } catch {
        throw error("authentication_unavailable", 503);
      }
      if (allowed !== true) throw error("unauthorized", 401);
    };
  }

  if (!config || typeof config !== "object" || Array.isArray(config) ||
      Object.keys(config).length !== 1 || !Object.hasOwn(config, "bearer_token")) {
    throw new TypeError("request_auth must be a function or { bearer_token }");
  }

  const secret = config.bearer_token;
  if (typeof secret !== "string" || Buffer.byteLength(secret) < 32 ||
      Buffer.byteLength(secret) > 4096 || /\s/.test(secret)) {
    throw new TypeError("request_auth.bearer_token must be 32-4096 non-whitespace bytes");
  }
  const expected = crypto.createHash("sha256").update(secret, "utf8").digest();

  return async (req) => {
    const raw = req.rawHeaders;
    const count = Array.isArray(raw)
      ? raw.filter((name, index) => index % 2 === 0 && name.toLowerCase() === "authorization").length
      : 0;
    const header = req.headers?.authorization;
    if (count > 1 || typeof header !== "string" || !/^Bearer [^\s]+$/i.test(header)) {
      throw error("unauthorized", 401);
    }
    const candidate = header.slice(7);
    if (Buffer.byteLength(candidate) > 4096) throw error("unauthorized", 401);
    const actual = crypto.createHash("sha256").update(candidate, "utf8").digest();
    if (!crypto.timingSafeEqual(actual, expected)) throw error("unauthorized", 401);
  };
}
