// Quorum-configuration safety rule for k-of-n witness quorums (shared with
// independent/python/quorum_safety.py and independent/go/quorumsafety.go;
// vectors in conformance/quorum-safety/).
//
// Two quorums of size k drawn from n witnesses share at least 2k - n
// witnesses. If f witnesses are faulty (equivocating, rolled back, or using a
// stolen key), two conflicting decisions can both reach quorum unless every
// overlap contains an honest witness, i.e. 2k - n >= f + 1. So:
//   safety_fault_tolerance   = 2k - n - 1  (faulty witnesses tolerated before
//                                           two conflicting quorums can form)
//   liveness_fault_tolerance = n - k       (unavailable witnesses tolerated
//                                           before no quorum can form at all)
// A configuration is accepted only when 1 <= k <= n <= 64 are integers and
// safety_fault_tolerance >= 1. That refuses every 2k <= n (quorums need not
// even intersect: 1-of-2, 2-of-4, 3-of-7 ...) and every 2k = n + 1 (they
// intersect in exactly one witness, so one faulty witness splits them:
// 1-of-1, 2-of-3, 3-of-5, 4-of-7 ...). There is no fallback: an unsafe
// configuration is refused, never rounded up or silently accepted.
// Note: n-of-n passes this rule (3-of-3 tolerates 2 faulty witnesses for
// safety) but tolerates zero unavailable witnesses; liveness_fault_tolerance
// is reported so a relying party can also require it.
export const QUORUM_SAFETY_RULE = "aml-quorum-safety/1: integers 1 <= k <= n <= 64 and 2k - n - 1 >= 1";
export const MAX_QUORUM_WITNESSES = 64;

export function evaluateQuorumSafety(threshold, witnessCount) {
  const out = (valid, reason, extra = {}) => ({ valid, reason, threshold, witness_count: witnessCount, ...extra });
  if (!Number.isSafeInteger(witnessCount)) return out(false, "witness_count_not_integer");
  if (!Number.isSafeInteger(threshold)) return out(false, "threshold_not_integer");
  if (witnessCount < 1 || witnessCount > MAX_QUORUM_WITNESSES) return out(false, "witness_count_out_of_range");
  if (threshold < 1 || threshold > witnessCount) return out(false, "threshold_out_of_range");
  const tolerances = {
    quorum_intersection: 2 * threshold - witnessCount,
    safety_fault_tolerance: 2 * threshold - witnessCount - 1,
    liveness_fault_tolerance: witnessCount - threshold
  };
  if (2 * threshold <= witnessCount) return out(false, "quorums_may_not_intersect", tolerances);
  if (tolerances.safety_fault_tolerance < 1) return out(false, "zero_fault_tolerance", tolerances);
  return out(true, null, tolerances);
}
