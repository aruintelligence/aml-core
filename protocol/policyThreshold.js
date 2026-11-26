// Policy threshold rule shared by governance policy-transition authorization
// and governance witness quorums (and by independent/python/policy_threshold.py
// and independent/go/policythreshold.go; vectors in conformance/policy-threshold/).
//
//   - threshold omitted (undefined / key absent): the documented default 1;
//   - threshold a positive safe integer: used as written;
//   - anything else (0, negative, fractional, string, boolean, null, object,
//     unsafe integer): a policy error "invalid_threshold" with threshold null.
// An explicit invalid threshold is never replaced by 1, because that would
// silently lower the threshold the policy author wrote.
export const POLICY_THRESHOLD_DEFAULT = 1;

export function resolvePolicyThreshold(policy) {
  const hasThreshold = policy !== null && typeof policy === "object" && Object.hasOwn(policy, "threshold")
    && policy.threshold !== undefined;
  if (!hasThreshold) return { threshold: POLICY_THRESHOLD_DEFAULT, error: null };
  const value = policy.threshold;
  if (Number.isSafeInteger(value) && value > 0) return { threshold: value, error: null };
  return { threshold: null, error: "invalid_threshold" };
}
