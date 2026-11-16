// Exit-status contract for verifier and validator commands.
//
// A successful verification must never imply authorization unless the
// complete authorization decision is explicitly true. `valid` reports
// internal consistency only.
//
//   0  authorized === true (decision mode), or a consistent result in an
//      explicitly requested --diagnostic-only mode, whose output says
//      NOT AN AUTHORIZATION DECISION and reports `authorized: false`.
//   3  consistent (`valid: true`) but not authorized.
//   other non-zero codes keep each command's existing meaning (invalid
//      input, usage or runtime error).

export const AML_EXIT_AUTHORIZED = 0;
export const AML_EXIT_NOT_AUTHORIZED = 3;
export const AML_DIAGNOSTIC_ONLY_FLAG = "--diagnostic-only";
export const AML_NOT_AN_AUTHORIZATION_DECISION = "NOT AN AUTHORIZATION DECISION";
// Kept for compatibility: no caller-supplied time is accepted for authorization.
export const COMMAND_AUTHORIZATION_CLOCK_SKEW_MS = 0;

const deny = (required, reasons) => ({
  schema: "aml-authorization-decision/1", authorized: false, decision: "deny",
  reasons: [...new Set(reasons)], required: [...required]
});

// Fail closed: every required condition must be an own property that is
// exactly `true`; unknown or missing conditions and evaluation errors deny.
export function commandAuthorizationDecision(conditions, required, denials) {
  try {
    if (!Array.isArray(required) || required.length === 0 || !denials || typeof denials !== "object") {
      return deny([], ["AML_AUTHZ_EVALUATION_ERROR"]);
    }
    if (conditions === null || typeof conditions !== "object" || Array.isArray(conditions)) {
      return deny(required, ["AML_AUTHZ_CONDITIONS_MISSING"]);
    }
    const reasons = [];
    for (const name of required) {
      if (!Object.hasOwn(conditions, name) || conditions[name] !== true) {
        reasons.push(Object.hasOwn(denials, name) ? denials[name] : "AML_AUTHZ_CONDITIONS_MISSING");
      }
    }
    if (Object.keys(conditions).some(name => !required.includes(name))) reasons.push("AML_AUTHZ_UNKNOWN_CONDITION");
    if (reasons.length) return deny(required, reasons);
    return { schema: "aml-authorization-decision/1", authorized: true, decision: "allow",
      reasons: ["AML_AUTHZ_ALLOW"], required: [...required] };
  } catch {
    return deny(Array.isArray(required) ? required : [], ["AML_AUTHZ_EVALUATION_ERROR"]);
  }
}

// The verifier trusts only its own clock. Any caller-supplied time (for
// example AML_VERIFY_AT or --now) is reported but never authorizes, however
// close it is to the local clock: a tolerance window lets the caller choose
// the freshness outcome near an expiry boundary.
export function trustedCommandClock(callerTime, localNowMs = Date.now()) {
  if (callerTime === null || callerTime === undefined || callerTime === "") return Number.isFinite(localNowMs);
  return false;
}

// Attach the decision to a result without changing `valid`.
export function withCommandAuthorization(result, decision, trustAssumptions = []) {
  return { ...result, authorized: decision.authorized === true, authorization: decision,
    remaining_trust_assumptions: [...trustAssumptions] };
}

// Present a result for output and choose the exit code. `invalidCode` is the
// command's existing failure code. Exit 0 requires `authorized === true` in
// decision mode; diagnostic mode reports authorized:false and is labelled.
export function commandOutcome(result, { diagnosticOnly = false, invalidCode = 1, consistent: consistentOption } = {}) {
  // `consistent` lets a command name its own verification field (for
  // example `verified`); it is only ever a precondition, never permission.
  const consistent = consistentOption === undefined ? result?.valid === true : consistentOption === true;
  if (diagnosticOnly) {
    const authorization = { ...(result?.authorization || {}), authorized: false, decision: "deny",
      reasons: ["AML_AUTHZ_DIAGNOSTIC_ONLY", ...((result?.authorization?.reasons) || [])
        .filter(r => r !== "AML_AUTHZ_ALLOW")] };
    return {
      output: { ...result, authorized: false, authorization, diagnostic_only: true,
        decision_use: AML_NOT_AN_AUTHORIZATION_DECISION },
      exitCode: consistent ? 0 : invalidCode
    };
  }
  const authorized = result?.authorized === true && result?.authorization?.authorized === true && consistent;
  return { output: { ...result, decision_use: authorized ? "authorization" : AML_NOT_AN_AUTHORIZATION_DECISION },
    exitCode: authorized ? AML_EXIT_AUTHORIZED : consistent ? AML_EXIT_NOT_AUTHORIZED : invalidCode };
}

export function diagnosticOnlyRequested(argv) {
  return Array.isArray(argv) && argv.includes(AML_DIAGNOSTIC_ONLY_FLAG);
}

// A pin is a 64-hex lowercase SHA-256 value the relying party obtained out of
// band. Only an exact match against the verified artifact counts.
export function isPin(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}
export function pinMatches(pin, actual) {
  return isPin(pin) && typeof actual === "string" && actual === pin;
}

// Remove `--name value` from argv. A flag without a value is a usage error.
export function takeOption(argv, name) {
  const rest = [];
  let value = null;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== name) { rest.push(argv[index]); continue; }
    const next = argv[index + 1];
    if (value !== null || next === undefined || next.startsWith("--")) throw new Error(`${name} requires exactly one value`);
    value = next;
    index += 1;
  }
  return { value, rest };
}

// One step for a verifier command: build the decision from explicit
// conditions, attach it, and pick the exit code. `consistent` is the
// command's own verification result (a precondition only).
export function decideCommand(verification, { consistent, conditions, required, denials, trust = [],
  diagnosticOnly = false, invalidCode = 1 }) {
  const result = withCommandAuthorization(verification,
    commandAuthorizationDecision(conditions, required, denials), trust);
  return commandOutcome(result, { diagnosticOnly, invalidCode, consistent: consistent === true });
}
