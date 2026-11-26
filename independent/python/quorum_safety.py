#!/usr/bin/env python3
"""k-of-n witness quorum safety rule (Python, stdlib only).

Same rule, reasons and fields as protocol/quorumSafety.js and
independent/go/quorumsafety.go (vectors: conformance/quorum-safety/):
accepted only when 1 <= k <= n <= 64 are (JavaScript-safe) integers and
safety_fault_tolerance = 2k - n - 1 >= 1. Unsafe configurations are refused,
never rounded up. liveness_fault_tolerance = n - k is reported, not enforced.

    python3 independent/python/quorum_safety.py conformance conformance/quorum-safety/vectors.json
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trust_config import strict_json  # noqa: E402

MAX_QUORUM_WITNESSES = 64
MAX_SAFE = 2 ** 53 - 1


def _safe_integer(value):
    """Number.isSafeInteger on a decoded JSON value; bool is never a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if -MAX_SAFE <= value <= MAX_SAFE else None
    if isinstance(value, float) and value == value and value not in (float("inf"), float("-inf")) and value.is_integer():
        return int(value) if -MAX_SAFE <= value <= MAX_SAFE else None
    return None


def evaluate_quorum_safety(threshold, witness_count):
    out = {"threshold": threshold, "witness_count": witness_count}
    n = _safe_integer(witness_count)
    if n is None:
        return {**out, "valid": False, "reason": "witness_count_not_integer"}
    k = _safe_integer(threshold)
    if k is None:
        return {**out, "valid": False, "reason": "threshold_not_integer"}
    if n < 1 or n > MAX_QUORUM_WITNESSES:
        return {**out, "valid": False, "reason": "witness_count_out_of_range"}
    if k < 1 or k > n:
        return {**out, "valid": False, "reason": "threshold_out_of_range"}
    tolerances = {"quorum_intersection": 2 * k - n, "safety_fault_tolerance": 2 * k - n - 1,
                  "liveness_fault_tolerance": n - k}
    if 2 * k <= n:
        return {**out, **tolerances, "valid": False, "reason": "quorums_may_not_intersect"}
    if tolerances["safety_fault_tolerance"] < 1:
        return {**out, **tolerances, "valid": False, "reason": "zero_fault_tolerance"}
    return {**out, **tolerances, "valid": True, "reason": None}


def main(argv):
    if len(argv) != 3 or argv[1] != "conformance":
        sys.stderr.write("usage: quorum_safety.py conformance <vectors.json>\n")
        return 2
    with open(argv[2], encoding="utf-8") as handle:
        vectors = strict_json(handle.read())
    results = []
    for c in vectors["cases"]:
        got = evaluate_quorum_safety(c["threshold"], c["witness_count"])
        results.append({k: got.get(k) for k in c["expect"]})
    print(json.dumps({"implementation": "python", "results": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
