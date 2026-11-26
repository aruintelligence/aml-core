#!/usr/bin/env python3
"""Policy threshold rule (Python, stdlib only).

Same rule and results as protocol/policyThreshold.js and
independent/go/policythreshold.go (vectors: conformance/policy-threshold/):
threshold omitted -> 1; a positive (JavaScript-safe) integer -> itself;
anything else -> error "invalid_threshold" with threshold None. An explicit
invalid threshold is never replaced by 1.

    python3 independent/python/policy_threshold.py conformance conformance/policy-threshold/vectors.json
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trust_config import strict_json  # noqa: E402

POLICY_THRESHOLD_DEFAULT = 1
MAX_SAFE = 2 ** 53 - 1


def resolve_policy_threshold(policy):
    if not isinstance(policy, dict) or "threshold" not in policy:
        return {"threshold": POLICY_THRESHOLD_DEFAULT, "error": None}
    value = policy["threshold"]
    if isinstance(value, bool):
        number = None
    elif isinstance(value, int):
        number = value
    elif isinstance(value, float) and value == value and value not in (float("inf"), float("-inf")) and value.is_integer():
        number = int(value)
    else:
        number = None
    if number is not None and 0 < number <= MAX_SAFE:
        return {"threshold": number, "error": None}
    return {"threshold": None, "error": "invalid_threshold"}


def main(argv):
    if len(argv) != 3 or argv[1] != "conformance":
        sys.stderr.write("usage: policy_threshold.py conformance <vectors.json>\n")
        return 2
    with open(argv[2], encoding="utf-8") as handle:
        vectors = strict_json(handle.read())
    results = [{"name": c["name"], "result": resolve_policy_threshold(strict_json(c["policy_json"]))} for c in vectors["cases"]]
    print(json.dumps({"implementation": "python", "results": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
