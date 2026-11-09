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
export const COMMAND_AUTHORIZATION_CLOCK_SKEW_MS = 1000;

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

// The verifier trusts only its own clock. A caller-supplied time (for
// example an environment override) is trusted only within the skew bound.
export function trustedCommandClock(callerTime, localNowMs = Date.now()) {
  if (callerTime === null || callerTime === undefined || callerTime === "") return Number.isFinite(localNowMs);
  const parsed = typeof callerTime === "number" ? callerTime : Date.parse(String(callerTime));
  return Number.isFinite(parsed) && Number.isFinite(localNowMs) &&
    Math.abs(parsed - localNowMs) <= COMMAND_AUTHORIZATION_CLOCK_SKEW_MS;
}

// Attach the decision to a result without changing `valid`.
export function withCommandAuthorization(result, decision, trustAssumptions = []) {
  return { ...result, authorized: decision.authorized === true, authorization: decision,
    remaining_trust_assumptions: [...trustAssumptions] };
}

// Present a result for output and choose the exit code. `invalidCode` is the
// command's existing failure code. Exit 0 requires `authorized === true` in
// decision mode; diagnostic mode reports authorized:false and is labelled.
export function commandOutcome(result, { diagnosticOnly = false, invalidCode = 1 } = {}) {
  const consistent = result?.valid === true;
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
